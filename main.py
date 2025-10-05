#!/usr/bin/env python3
"""
AI-Driven Next-Generation Firewall (NGFW)
Main application entry point with FastAPI backend
"""

import asyncio
import logging
import signal
import sys
from contextlib import asynccontextmanager
from typing import Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from src.core.waf_engine import WAFEngine
from src.core.config import Settings
from src.api.routes import api_router
from src.dashboard.app import create_dashboard_app
from src.utils.logger import setup_logging
from src.monitoring.metrics import setup_metrics

# Global WAF engine instance
waf_engine: WAFEngine = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    global waf_engine
    
    # Startup
    logger = logging.getLogger(__name__)
    logger.info("Starting AI-Driven WAF System...")
    
    try:
        # Initialize WAF engine
        settings = Settings()
        waf_engine = WAFEngine(settings)
        await waf_engine.initialize()
        
        # Start background tasks
        asyncio.create_task(waf_engine.start_packet_capture())
        asyncio.create_task(waf_engine.start_threat_analysis())
        
        logger.info("WAF System started successfully")
        yield
        
    except Exception as e:
        logger.error(f"Failed to start WAF System: {e}")
        raise
    finally:
        # Shutdown
        logger.info("Shutting down WAF System...")
        if waf_engine:
            await waf_engine.shutdown()
        logger.info("WAF System shutdown complete")

def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    
    app = FastAPI(
        title="AI-Driven Next-Generation Firewall",
        description="Advanced WAF with AI/ML threat detection and Zero Trust implementation",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=lifespan
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include API routes
    app.include_router(api_router, prefix="/api/v1")
    
    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """Health check endpoint"""
        return {
            "status": "healthy",
            "version": "1.0.0",
            "waf_engine": "running" if waf_engine and waf_engine.is_running else "stopped"
        }
    
    # Get WAF engine dependency
    @app.get("/waf-engine")
    async def get_waf_engine():
        """Get WAF engine instance"""
        if not waf_engine:
            raise HTTPException(status_code=503, detail="WAF engine not initialized")
        return waf_engine
    
    return app

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    def signal_handler(signum, frame):
        logging.info(f"Received signal {signum}, shutting down...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

async def run_dashboard():
    """Run the dashboard application"""
    dashboard_app = create_dashboard_app()
    import threading
    
    def run_dash():
        dashboard_app.run_server(host="0.0.0.0", port=8080, debug=False)
    
    dashboard_thread = threading.Thread(target=run_dash, daemon=True)
    dashboard_thread.start()

if __name__ == "__main__":
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Setup signal handlers
    setup_signal_handlers()
    
    # Setup metrics
    setup_metrics()
    
    # Create FastAPI app
    app = create_app()
    
    # Start dashboard in background
    asyncio.create_task(run_dashboard())
    
    # Run the application
    logger.info("Starting WAF API server on port 8000")
    logger.info("Dashboard will be available on port 8080")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True,
        reload=False
    )