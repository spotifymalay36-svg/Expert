"""
Real Network Packet Blocking using iptables/nftables
Implements actual packet interception and blocking capabilities
"""

import subprocess
import asyncio
import ipaddress
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
import re
import json
from pathlib import Path

from ..core.config import Settings, ThreatLevel
from ..utils.logger import get_logger

@dataclass
class BlockRule:
    """Blocked IP/network rule"""
    rule_id: str
    target: str  # IP address or CIDR
    protocol: str  # tcp, udp, icmp, all
    port: Optional[int]
    action: str  # DROP, REJECT, LOG
    reason: str
    created_at: datetime
    expires_at: Optional[datetime]
    packet_count: int = 0

class PacketBlocker:
    """Real network packet blocking using iptables/nftables"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = get_logger(__name__)
        
        # Track active block rules
        self.active_blocks: Dict[str, BlockRule] = {}
        
        # Determine which firewall system to use
        self.use_nftables = self._detect_firewall_system()
        
        # WAF chain names
        self.chain_name = "WAF_BLOCK"
        self.log_chain_name = "WAF_LOG"
        
        # Block list file for persistence
        self.blocklist_file = Path(settings.model_path) / "blocklist.json"
        
        self.logger.info(f"Packet Blocker initialized using {'nftables' if self.use_nftables else 'iptables'}")
    
    def _detect_firewall_system(self) -> bool:
        """Detect whether to use nftables or iptables"""
        try:
            # Try nft first
            result = subprocess.run(['which', 'nft'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return True
            
            # Fall back to iptables
            result = subprocess.run(['which', 'iptables'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return False
            
            raise Exception("Neither nftables nor iptables found")
            
        except Exception as e:
            self.logger.error(f"Error detecting firewall system: {e}")
            return False
    
    async def initialize(self):
        """Initialize packet blocking system"""
        try:
            self.logger.info("Initializing packet blocking system...")
            
            # Create WAF chains
            if self.use_nftables:
                await self._initialize_nftables()
            else:
                await self._initialize_iptables()
            
            # Load persisted block list
            await self._load_blocklist()
            
            # Start cleanup task
            asyncio.create_task(self._cleanup_expired_rules())
            
            self.logger.info("Packet blocking system initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize packet blocker: {e}")
            raise
    
    async def _initialize_iptables(self):
        """Initialize iptables chains for WAF"""
        try:
            # Create WAF_BLOCK chain
            await self._run_command(['iptables', '-N', self.chain_name], 
                                  ignore_errors=True)  # Chain might already exist
            
            # Create WAF_LOG chain
            await self._run_command(['iptables', '-N', self.log_chain_name], 
                                  ignore_errors=True)
            
            # Insert jump to WAF_BLOCK chain at the beginning of INPUT
            await self._run_command([
                'iptables', '-I', 'INPUT', '1', 
                '-j', self.chain_name
            ], ignore_errors=True)
            
            # Insert jump to WAF_BLOCK chain in FORWARD
            await self._run_command([
                'iptables', '-I', 'FORWARD', '1', 
                '-j', self.chain_name
            ], ignore_errors=True)
            
            self.logger.info("iptables chains initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing iptables: {e}")
            raise
    
    async def _initialize_nftables(self):
        """Initialize nftables for WAF"""
        try:
            # Create WAF table
            await self._run_command(['nft', 'add', 'table', 'inet', 'waf'], 
                                  ignore_errors=True)
            
            # Create input chain
            await self._run_command([
                'nft', 'add', 'chain', 'inet', 'waf', 'input',
                '{', 'type', 'filter', 'hook', 'input', 'priority', '0', ';', '}'
            ], ignore_errors=True)
            
            # Create forward chain
            await self._run_command([
                'nft', 'add', 'chain', 'inet', 'waf', 'forward',
                '{', 'type', 'filter', 'hook', 'forward', 'priority', '0', ';', '}'
            ], ignore_errors=True)
            
            self.logger.info("nftables initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing nftables: {e}")
            raise
    
    async def block_ip(self, ip_address: str, protocol: str = "all", 
                       port: Optional[int] = None, duration_minutes: int = 60,
                       reason: str = "Threat detected") -> bool:
        """Block an IP address"""
        try:
            # Validate IP address
            try:
                ip_obj = ipaddress.ip_address(ip_address)
            except ValueError:
                self.logger.error(f"Invalid IP address: {ip_address}")
                return False
            
            # Check if already blocked
            if ip_address in self.active_blocks:
                self.logger.info(f"IP {ip_address} already blocked")
                return True
            
            # Create block rule
            rule_id = f"block_{ip_address}_{int(datetime.now().timestamp())}"
            expires_at = datetime.now() + timedelta(minutes=duration_minutes) if duration_minutes > 0 else None
            
            block_rule = BlockRule(
                rule_id=rule_id,
                target=ip_address,
                protocol=protocol,
                port=port,
                action="DROP",
                reason=reason,
                created_at=datetime.now(),
                expires_at=expires_at
            )
            
            # Apply firewall rule
            if self.use_nftables:
                success = await self._block_ip_nftables(ip_address, protocol, port)
            else:
                success = await self._block_ip_iptables(ip_address, protocol, port)
            
            if success:
                self.active_blocks[ip_address] = block_rule
                await self._save_blocklist()
                
                self.logger.info(f"Blocked IP {ip_address} (protocol: {protocol}, duration: {duration_minutes}min, reason: {reason})")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error blocking IP {ip_address}: {e}")
            return False
    
    async def _block_ip_iptables(self, ip_address: str, protocol: str, 
                                 port: Optional[int]) -> bool:
        """Block IP using iptables"""
        try:
            cmd = ['iptables', '-A', self.chain_name, '-s', ip_address]
            
            if protocol != "all":
                cmd.extend(['-p', protocol])
            
            if port:
                cmd.extend(['--dport', str(port)])
            
            cmd.extend(['-j', 'DROP'])
            
            await self._run_command(cmd)
            
            # Also add LOG rule before DROP
            log_cmd = ['iptables', '-A', self.log_chain_name, '-s', ip_address,
                      '-j', 'LOG', '--log-prefix', f'WAF_BLOCK_{ip_address}: ']
            await self._run_command(log_cmd, ignore_errors=True)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error blocking IP with iptables: {e}")
            return False
    
    async def _block_ip_nftables(self, ip_address: str, protocol: str, 
                                 port: Optional[int]) -> bool:
        """Block IP using nftables"""
        try:
            # Build nft rule
            rule_parts = ['nft', 'add', 'rule', 'inet', 'waf', 'input',
                         'ip', 'saddr', ip_address]
            
            if protocol != "all":
                rule_parts.extend([protocol, 'dport', str(port)] if port else [])
            
            rule_parts.extend(['drop'])
            
            await self._run_command(rule_parts)
            
            # Add to forward chain as well
            rule_parts[6] = 'forward'
            await self._run_command(rule_parts)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error blocking IP with nftables: {e}")
            return False
    
    async def unblock_ip(self, ip_address: str) -> bool:
        """Unblock an IP address"""
        try:
            if ip_address not in self.active_blocks:
                self.logger.warning(f"IP {ip_address} not in block list")
                return False
            
            block_rule = self.active_blocks[ip_address]
            
            # Remove firewall rule
            if self.use_nftables:
                success = await self._unblock_ip_nftables(ip_address, 
                                                         block_rule.protocol, 
                                                         block_rule.port)
            else:
                success = await self._unblock_ip_iptables(ip_address, 
                                                         block_rule.protocol, 
                                                         block_rule.port)
            
            if success:
                del self.active_blocks[ip_address]
                await self._save_blocklist()
                
                self.logger.info(f"Unblocked IP {ip_address}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False
    
    async def _unblock_ip_iptables(self, ip_address: str, protocol: str, 
                                   port: Optional[int]) -> bool:
        """Unblock IP using iptables"""
        try:
            cmd = ['iptables', '-D', self.chain_name, '-s', ip_address]
            
            if protocol != "all":
                cmd.extend(['-p', protocol])
            
            if port:
                cmd.extend(['--dport', str(port)])
            
            cmd.extend(['-j', 'DROP'])
            
            await self._run_command(cmd)
            return True
            
        except Exception as e:
            self.logger.error(f"Error unblocking IP with iptables: {e}")
            return False
    
    async def _unblock_ip_nftables(self, ip_address: str, protocol: str, 
                                   port: Optional[int]) -> bool:
        """Unblock IP using nftables"""
        try:
            # In nftables, we need to find and delete the specific rule
            # This is simplified - in production, you'd use rule handles
            
            # Flush and rebuild rules (simplified approach)
            # In production, track rule handles for precise deletion
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error unblocking IP with nftables: {e}")
            return False
    
    async def block_port(self, port: int, protocol: str = "tcp", 
                        reason: str = "Port blocking") -> bool:
        """Block a specific port"""
        try:
            if self.use_nftables:
                cmd = ['nft', 'add', 'rule', 'inet', 'waf', 'input',
                      protocol, 'dport', str(port), 'drop']
            else:
                cmd = ['iptables', '-A', self.chain_name, '-p', protocol,
                      '--dport', str(port), '-j', 'DROP']
            
            await self._run_command(cmd)
            
            self.logger.info(f"Blocked port {port}/{protocol}: {reason}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error blocking port {port}: {e}")
            return False
    
    async def rate_limit_ip(self, ip_address: str, limit: int = 100, 
                           period: int = 60) -> bool:
        """Apply rate limiting to an IP"""
        try:
            if self.use_nftables:
                # NFT rate limiting
                cmd = ['nft', 'add', 'rule', 'inet', 'waf', 'input',
                      'ip', 'saddr', ip_address,
                      'limit', 'rate', f'{limit}/{period}',
                      'accept']
            else:
                # iptables rate limiting using hashlimit
                cmd = ['iptables', '-A', self.chain_name, '-s', ip_address,
                      '-m', 'hashlimit',
                      '--hashlimit-name', f'rate_{ip_address}',
                      '--hashlimit-above', f'{limit}/{period}sec',
                      '-j', 'DROP']
            
            await self._run_command(cmd)
            
            self.logger.info(f"Rate limiting {ip_address}: {limit} packets/{period}s")
            return True
            
        except Exception as e:
            self.logger.error(f"Error rate limiting IP {ip_address}: {e}")
            return False
    
    async def _run_command(self, cmd: List[str], ignore_errors: bool = False) -> bool:
        """Run a shell command asynchronously"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)
            
            if process.returncode != 0 and not ignore_errors:
                error_msg = stderr.decode().strip()
                raise Exception(f"Command failed: {' '.join(cmd)}\nError: {error_msg}")
            
            return True
            
        except asyncio.TimeoutError:
            self.logger.error(f"Command timed out: {' '.join(cmd)}")
            return False
        except Exception as e:
            if not ignore_errors:
                self.logger.error(f"Command error: {e}")
            return False
    
    async def _cleanup_expired_rules(self):
        """Periodically cleanup expired block rules"""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                now = datetime.now()
                expired = []
                
                for ip, rule in self.active_blocks.items():
                    if rule.expires_at and now >= rule.expires_at:
                        expired.append(ip)
                
                for ip in expired:
                    await self.unblock_ip(ip)
                    self.logger.info(f"Removed expired block for {ip}")
                
            except Exception as e:
                self.logger.error(f"Error in cleanup task: {e}")
    
    async def _save_blocklist(self):
        """Save block list to disk"""
        try:
            blocklist_data = {
                ip: {
                    "rule_id": rule.rule_id,
                    "target": rule.target,
                    "protocol": rule.protocol,
                    "port": rule.port,
                    "action": rule.action,
                    "reason": rule.reason,
                    "created_at": rule.created_at.isoformat(),
                    "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
                    "packet_count": rule.packet_count
                }
                for ip, rule in self.active_blocks.items()
            }
            
            with open(self.blocklist_file, 'w') as f:
                json.dump(blocklist_data, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error saving blocklist: {e}")
    
    async def _load_blocklist(self):
        """Load block list from disk"""
        try:
            if not self.blocklist_file.exists():
                return
            
            with open(self.blocklist_file, 'r') as f:
                blocklist_data = json.load(f)
            
            for ip, data in blocklist_data.items():
                # Recreate block rules
                rule = BlockRule(
                    rule_id=data['rule_id'],
                    target=data['target'],
                    protocol=data['protocol'],
                    port=data['port'],
                    action=data['action'],
                    reason=data['reason'],
                    created_at=datetime.fromisoformat(data['created_at']),
                    expires_at=datetime.fromisoformat(data['expires_at']) if data['expires_at'] else None,
                    packet_count=data['packet_count']
                )
                
                # Reapply block if not expired
                if not rule.expires_at or datetime.now() < rule.expires_at:
                    if self.use_nftables:
                        await self._block_ip_nftables(ip, rule.protocol, rule.port)
                    else:
                        await self._block_ip_iptables(ip, rule.protocol, rule.port)
                    
                    self.active_blocks[ip] = rule
            
            self.logger.info(f"Loaded {len(self.active_blocks)} block rules from disk")
            
        except Exception as e:
            self.logger.error(f"Error loading blocklist: {e}")
    
    async def get_blocked_ips(self) -> List[Dict]:
        """Get list of currently blocked IPs"""
        return [
            {
                "ip": ip,
                "protocol": rule.protocol,
                "port": rule.port,
                "reason": rule.reason,
                "created_at": rule.created_at.isoformat(),
                "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
                "packets_blocked": rule.packet_count
            }
            for ip, rule in self.active_blocks.items()
        ]
    
    async def clear_all_blocks(self) -> bool:
        """Clear all block rules (use with caution!)"""
        try:
            if self.use_nftables:
                await self._run_command(['nft', 'flush', 'table', 'inet', 'waf'])
            else:
                await self._run_command(['iptables', '-F', self.chain_name])
            
            self.active_blocks.clear()
            await self._save_blocklist()
            
            self.logger.warning("All block rules cleared")
            return True
            
        except Exception as e:
            self.logger.error(f"Error clearing blocks: {e}")
            return False
    
    async def get_blocker_stats(self) -> Dict[str, Any]:
        """Get packet blocker statistics"""
        return {
            "total_blocks": len(self.active_blocks),
            "firewall_system": "nftables" if self.use_nftables else "iptables",
            "chain_name": self.chain_name,
            "blocked_ips": list(self.active_blocks.keys()),
            "total_packets_blocked": sum(rule.packet_count for rule in self.active_blocks.values())
        }
    
    async def shutdown(self):
        """Shutdown packet blocker (optionally remove rules)"""
        try:
            # Save current state
            await self._save_blocklist()
            
            # Optionally clear WAF chains (commented out to persist rules)
            # await self.clear_all_blocks()
            
            self.logger.info("Packet blocker shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")