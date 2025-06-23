# YL-analysis API文档

## 技术栈概述

后端API基于aiohttp库实现，采用模块化的路由管理设计，使用异步编程模型处理请求。

## 核心架构

- **aiohttp框架**：提供异步HTTP服务器和客户端功能
- **模块化路由**：所有router类都继承自RouterBase基类
- **服务管理器**：使用service_manager统一管理应用生命周期和回调函数
- **异步队列**：使用analysis_queue管理分析任务的执行

## aiohttp框架优势

1. **异步处理能力**：基于Python的asyncio库，支持高并发请求处理
2. **轻量级设计**：相比Django和Flask等框架，aiohttp更加轻量，启动速度快
3. **灵活性**：提供低级API，允许开发者根据需求进行定制
4. **WebSocket支持**：内置WebSocket支持，便于实现实时通信
5. **中间件机制**：支持请求处理管道，便于实现横切关注点

## 模块化设计优势

1. **代码组织清晰**：每个功能模块独立封装，便于维护
2. **职责分离**：每个路由模块负责特定的功能领域
3. **可扩展性**：新功能可以通过添加新的路由模块轻松集成
4. **可测试性**：模块化设计便于单元测试和集成测试

## 主要模块

- **RouterBase**：所有路由类的基类，提供通用功能
- **AnalysisRouter**：处理代码分析相关的API
- **ProjectsRouter**：管理项目相关的API
- **SettingsRouter**：处理系统设置相关的API
- **ServiceManager**：管理应用生命周期和服务注册
- **AnalysisQueueManager**：管理分析任务队列
- **TerminalService**：管理终端日志和WebSocket通信

## 详细文档

- [API接口设计](./api_interface.md)
- [路由系统](./routing_system.md)
- [服务管理器](./service_manager.md)
- [分析队列](./analysis_queue.md)
- [终端服务](./terminal_service.md)
- [配置管理](./config_management.md)
- [项目管理](./project_management.md)
- [漏洞分析](./vulnerability_analysis.md)
- [漏洞类型](./vulnerability_types.md)
- [LLM集成](./llm_integration.md)