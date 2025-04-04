#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
查询性能分析模块

提供SQL查询日志记录、慢查询分析和查询执行计划分析功能
"""

import time
import logging
import json
import asyncio
import re
from collections import deque, defaultdict
from typing import Dict, List, Any, Optional, Set, Tuple, Union, Deque
from dataclasses import dataclass, field

from tortoise import Tortoise
from tortoise.backends.base.schema_generator import BaseSchemaGenerator

logger = logging.getLogger("app.database")

# 最大记录的查询数
MAX_QUERY_LOGS = 1000
# 最大记录的慢查询数
MAX_SLOW_QUERIES = 100
# 慢查询阈值（秒）
SLOW_QUERY_THRESHOLD = 0.5

# 查询日志队列
_query_logs: Deque[Dict[str, Any]] = deque(maxlen=MAX_QUERY_LOGS)
# 慢查询日志队列
_slow_query_logs: Deque[Dict[str, Any]] = deque(maxlen=MAX_SLOW_QUERIES)
# 查询统计信息
_query_stats = {
    "total_queries": 0,
    "total_slow_queries": 0,
    "total_query_time": 0.0,
    "avg_query_time": 0.0,
    "max_query_time": 0.0,
    "min_query_time": float('inf'),
}
# 查询类型统计
_query_type_stats: Dict[str, Dict[str, Any]] = defaultdict(
    lambda: {"count": 0, "total_time": 0.0, "avg_time": 0.0, "max_time": 0.0}
)
# 锁，防止并发修改
_logs_lock = asyncio.Lock()


@dataclass
class QueryInfo:
    """查询信息数据类"""
    sql: str
    params: Optional[List[Any]] = None
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    duration: Optional[float] = None
    query_type: Optional[str] = None
    source: Optional[str] = None
    error: Optional[str] = None
    
    def __post_init__(self):
        # 识别查询类型
        if self.query_type is None:
            self.identify_query_type()
    
    def identify_query_type(self) -> None:
        """识别SQL查询类型"""
        sql = self.sql.strip().upper()
        
        if sql.startswith("SELECT"):
            self.query_type = "SELECT"
        elif sql.startswith("INSERT"):
            self.query_type = "INSERT"
        elif sql.startswith("UPDATE"):
            self.query_type = "UPDATE"
        elif sql.startswith("DELETE"):
            self.query_type = "DELETE"
        elif sql.startswith("CREATE"):
            self.query_type = "CREATE"
        elif sql.startswith("ALTER"):
            self.query_type = "ALTER"
        elif sql.startswith("DROP"):
            self.query_type = "DROP"
        else:
            self.query_type = "OTHER"
    
    def complete(self, error: Optional[str] = None) -> None:
        """
        完成查询
        
        Args:
            error: 错误信息（如有）
        """
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        self.error = error
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典表示"""
        return {
            "sql": self.sql,
            "params": self.params,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "query_type": self.query_type,
            "source": self.source,
            "error": self.error,
        }


async def log_query(
    sql: str,
    params: Optional[List[Any]] = None,
    source: Optional[str] = None
) -> Dict[str, Any]:
    """
    记录SQL查询日志

    Args:
        sql: SQL查询字符串
        params: 查询参数
        source: 查询来源（函数名或模块）

    Returns:
        Dict[str, Any]: 查询日志信息
    """
    global _query_stats
    
    # 创建查询信息对象
    query_info = QueryInfo(sql=sql, params=params, source=source)
    
    try:
        # 执行查询（通常由调用者执行，这里只是日志记录）
        return query_info.to_dict()
    except Exception as e:
        query_info.complete(error=str(e))
        raise
    finally:
        query_info.complete()
        
        # 更新统计信息
        async with _logs_lock:
            # 添加到查询日志
            _query_logs.append(query_info.to_dict())
            
            # 更新查询统计
            duration = query_info.duration or 0
            _query_stats["total_queries"] += 1
            _query_stats["total_query_time"] += duration
            _query_stats["avg_query_time"] = _query_stats["total_query_time"] / _query_stats["total_queries"]
            
            if duration > _query_stats["max_query_time"]:
                _query_stats["max_query_time"] = duration
                
            if duration < _query_stats["min_query_time"]:
                _query_stats["min_query_time"] = duration
            
            # 更新查询类型统计
            query_type = query_info.query_type or "UNKNOWN"
            _query_type_stats[query_type]["count"] += 1
            _query_type_stats[query_type]["total_time"] += duration
            _query_type_stats[query_type]["avg_time"] = (
                _query_type_stats[query_type]["total_time"] / 
                _query_type_stats[query_type]["count"]
            )
            
            if duration > _query_type_stats[query_type]["max_time"]:
                _query_type_stats[query_type]["max_time"] = duration
            
            # 记录慢查询
            if duration > SLOW_QUERY_THRESHOLD:
                _slow_query_logs.append(query_info.to_dict())
                _query_stats["total_slow_queries"] += 1


async def get_query_logs(
    limit: int = 50,
    query_type: Optional[str] = None,
    min_duration: Optional[float] = None,
    max_duration: Optional[float] = None,
    source: Optional[str] = None
) -> Dict[str, Any]:
    """
    获取查询日志

    Args:
        limit: 返回的日志数量限制
        query_type: 过滤特定类型的查询
        min_duration: 最小持续时间（秒）
        max_duration: 最大持续时间（秒）
        source: 过滤特定来源的查询

    Returns:
        Dict[str, Any]: 查询日志和统计信息
    """
    async with _logs_lock:
        # 过滤查询日志
        filtered_logs = list(_query_logs)
        
        if query_type:
            filtered_logs = [log for log in filtered_logs if log.get("query_type") == query_type]
        
        if min_duration is not None:
            filtered_logs = [log for log in filtered_logs if log.get("duration", 0) >= min_duration]
        
        if max_duration is not None:
            filtered_logs = [log for log in filtered_logs if log.get("duration", 0) <= max_duration]
        
        if source:
            filtered_logs = [log for log in filtered_logs if log.get("source") == source]
        
        # 按持续时间降序排序
        filtered_logs.sort(key=lambda x: x.get("duration", 0), reverse=True)
        
        # 限制返回数量
        filtered_logs = filtered_logs[:limit]
        
        return {
            "logs": filtered_logs,
            "stats": _query_stats,
            "type_stats": dict(_query_type_stats)
        }


async def get_slow_queries(limit: int = 20) -> List[Dict[str, Any]]:
    """
    获取慢查询日志

    Args:
        limit: 返回的日志数量限制

    Returns:
        List[Dict[str, Any]]: 慢查询日志列表
    """
    async with _logs_lock:
        # 按持续时间降序排序
        logs = sorted(
            list(_slow_query_logs),
            key=lambda x: x.get("duration", 0),
            reverse=True
        )
        return logs[:limit]


async def analyze_query_plan(
    sql: str,
    params: Optional[List[Any]] = None,
    conn_name: str = "default"
) -> Dict[str, Any]:
    """
    分析查询执行计划

    对于MySQL，使用EXPLAIN
    对于PostgreSQL，使用EXPLAIN ANALYZE
    对于SQLite，执行查询分析

    Args:
        sql: 要分析的SQL查询
        params: 查询参数
        conn_name: 连接名称

    Returns:
        Dict[str, Any]: 查询执行计划分析
    """
    if not Tortoise._inited:
        return {"error": "Tortoise ORM未初始化"}
    
    conn = Tortoise.get_connection(conn_name)
    dialect = conn.capabilities.dialect
    
    try:
        if dialect == "mysql":
            explain_sql = f"EXPLAIN {sql}"
            explain_result, _ = await conn.execute_query(explain_sql, params)
            
            # 尝试获取索引使用情况
            index_usage = []
            for row in explain_result:
                if "key" in row and row["key"]:
                    index_usage.append({
                        "table": row.get("table", ""),
                        "index": row["key"],
                        "key_len": row.get("key_len", ""),
                        "ref": row.get("ref", ""),
                    })
            
            return {
                "dialect": "mysql",
                "plan": explain_result,
                "index_usage": index_usage,
                "recommendations": _generate_mysql_recommendations(explain_result)
            }
            
        elif dialect == "postgres":
            explain_sql = f"EXPLAIN (ANALYZE, COSTS, VERBOSE, BUFFERS, FORMAT JSON) {sql}"
            explain_result, _ = await conn.execute_query(explain_sql, params)
            
            # PostgreSQL返回JSON格式的执行计划
            plan_json = explain_result[0]["QUERY PLAN"]
            
            return {
                "dialect": "postgres",
                "plan": plan_json,
                "recommendations": _generate_postgres_recommendations(plan_json)
            }
            
        elif dialect == "sqlite":
            # SQLite没有内置的EXPLAIN ANALYZE，只有基础的EXPLAIN
            explain_sql = f"EXPLAIN QUERY PLAN {sql}"
            explain_result, _ = await conn.execute_query(explain_sql, params)
            
            # 执行实际查询并计时
            start_time = time.time()
            await conn.execute_query(sql, params)
            duration = time.time() - start_time
            
            return {
                "dialect": "sqlite",
                "plan": explain_result,
                "duration": duration,
                "recommendations": _generate_sqlite_recommendations(explain_result)
            }
            
        else:
            return {
                "dialect": dialect,
                "error": f"不支持的数据库类型: {dialect}"
            }
    except Exception as e:
        return {
            "error": f"查询计划分析失败: {str(e)}",
            "dialect": dialect
        }


def _generate_mysql_recommendations(explain_result: List[Dict[str, Any]]) -> List[str]:
    """
    根据MySQL EXPLAIN结果生成优化建议

    Args:
        explain_result: MySQL EXPLAIN的结果

    Returns:
        List[str]: 优化建议列表
    """
    recommendations = []
    
    for row in explain_result:
        # 检查表扫描
        if row.get("type") in ["ALL"]:
            table = row.get("table", "未知表")
            recommendations.append(f"表 '{table}' 执行了全表扫描，考虑添加索引")
        
        # 检查索引使用
        if not row.get("key") and row.get("possible_keys"):
            table = row.get("table", "未知表")
            recommendations.append(f"表 '{table}' 有可用索引但未使用，可能需要优化查询或强制使用索引")
        
        # 检查临时表
        if row.get("Extra", "").find("Using temporary") >= 0:
            recommendations.append("查询使用了临时表，考虑优化GROUP BY或ORDER BY子句")
        
        # 检查文件排序
        if row.get("Extra", "").find("Using filesort") >= 0:
            recommendations.append("查询执行了文件排序，考虑为ORDER BY子句添加索引")
    
    # 检查连接优化
    if len(explain_result) > 1:
        has_nested_loop = any(row.get("select_type") == "DEPENDENT SUBQUERY" for row in explain_result)
        if has_nested_loop:
            recommendations.append("查询包含相关子查询，考虑重写为JOIN以提高性能")
    
    return recommendations


def _generate_postgres_recommendations(plan_json: List[Dict[str, Any]]) -> List[str]:
    """
    根据PostgreSQL EXPLAIN ANALYZE结果生成优化建议

    Args:
        plan_json: PostgreSQL EXPLAIN ANALYZE的结果

    Returns:
        List[str]: 优化建议列表
    """
    recommendations = []
    
    def analyze_node(node):
        """递归分析执行计划节点"""
        node_type = node.get("Node Type", "")
        
        # 检查顺序扫描
        if node_type == "Seq Scan":
            relation = node.get("Relation Name", "未知表")
            recommendations.append(f"表 '{relation}' 执行了顺序扫描，考虑添加索引")
        
        # 检查高成本操作
        if "Total Cost" in node and node["Total Cost"] > 1000:
            recommendations.append(f"发现高成本操作: {node_type}，成本为 {node['Total Cost']}")
        
        # 检查哈希连接和嵌套循环
        if node_type == "Hash Join" and node.get("Join Type") == "Inner":
            if "Plans" in node and len(node["Plans"]) == 2:
                if node["Plans"][1].get("Node Type") == "Hash" and node["Plans"][1].get("Rows", 0) > 1000:
                    recommendations.append("大表哈希连接可能消耗大量内存，考虑优化JOIN顺序或使用索引")
        
        # 递归检查子节点
        for child in node.get("Plans", []):
            analyze_node(child)
    
    # 从根节点开始分析
    if plan_json and len(plan_json) > 0:
        analyze_node(plan_json[0])
    
    return recommendations


def _generate_sqlite_recommendations(explain_result: List[Dict[str, Any]]) -> List[str]:
    """
    根据SQLite EXPLAIN QUERY PLAN结果生成优化建议

    Args:
        explain_result: SQLite EXPLAIN QUERY PLAN的结果

    Returns:
        List[str]: 优化建议列表
    """
    recommendations = []
    
    for row in explain_result:
        detail = row.get("detail", "")
        
        # 检查表扫描
        if "SCAN TABLE" in detail and "USING INDEX" not in detail:
            table_match = re.search(r"SCAN TABLE (\w+)", detail)
            if table_match:
                table = table_match.group(1)
                recommendations.append(f"表 '{table}' 执行了全表扫描，考虑添加索引")
        
        # 检查临时表和临时B树
        if "USE TEMP" in detail or "TEMP B-TREE" in detail:
            recommendations.append("查询使用了临时表或临时B树，可能影响性能")
    
    # 如果有多表操作但没有使用索引
    tables_scanned = len(set(re.findall(r"SCAN TABLE (\w+)", " ".join(row.get("detail", "") for row in explain_result))))
    if tables_scanned > 1 and not any("USING INDEX" in row.get("detail", "") for row in explain_result):
        recommendations.append("多表查询未使用索引，考虑为JOIN条件添加索引")
    
    return recommendations 