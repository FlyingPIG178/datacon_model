#!/usr/bin/env python3
import sys
import os
import logging
import asyncio
import argparse
from aiohttp import web
from api import create_app

# 添加当前目录到Python路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def parse_args():
    parser = argparse.ArgumentParser(description="启动分析服务")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="监听地址")
    parser.add_argument("--port", type=int, default=5000, help="监听端口")
    parser.add_argument("--log-level", type=str, default="info", help="日志级别")
    
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    app = create_app()
    
    # 配置日志
    log_level = getattr(logging, args.log_level.upper())
    logger = logging.getLogger("server")
    # logging.basicConfig(
    #     level=log_level,
    #     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    # )
    
    # 确保所有logger都使用相同的配置
    # for name in logging.root.manager.loggerDict:
    #     logger = logging.getLogger(name)
    #     logger.setLevel(log_level)
    
    # 设置特定logger的级别
    logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
    logger.info(f"启动分析服务器，监听 {args.host}:{args.port}")
    
    web.run_app(app, host=args.host, port=args.port) 