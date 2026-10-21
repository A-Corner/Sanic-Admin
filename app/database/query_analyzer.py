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


# 只读分析允许的语句：单条 SELECT，或以 WITH 开头的单条查询
_READONLY_START_RE = re.compile(r"^\s*(SELECT|WITH)\b", re.IGNORECASE)
# 出现在语句中任意位置即拒绝的写入/DDL/管理类关键字（整词匹配，宁可误拒不可漏放）
_FORBIDDEN_SQL_RE = re.compile(
    r"\b(INSERT|UPDATE|DELETE|REPLACE|MERGE|UPSERT|DROP|ALTER|CREATE|TRUNCATE|RENAME|"
    r"GRANT|REVOKE|ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|ANALYZE|CALL|EXEC|EXECUTE|COPY|"
    r"LOCK|SET|INTO|LOAD|HANDLER|DO)\b",
    re.IGNORECASE,
)


# 纵深防御：有副作用或会读写文件/阻塞/外连的函数（后面跟左括号时拒绝）
_FORBIDDEN_FUNC_RE = re.compile(
    r"\b(load_extension|pg_sleep\w*|sleep|benchmark|lo_\w+|pg_read_\w+|pg_ls_\w+|pg_stat_file|"
    r"nextval|setval|dblink\w*|load_file|get_lock|release_lock|set_config|"
    r"pg_terminate_backend|pg_cancel_backend|pg_advisory_lock\w*|pg_notify|pg_reload_conf|writefile|readfile|edit|fts3_tokenizer)\s*\(",
    re.IGNORECASE,
)

# 带引号/反引号/方括号的标识符后直接跟左括号（函数调用写法）可绕过上面的名称匹配，只读分析不需要，直接拒绝
_QUOTED_CALL_RE = re.compile(r'["`\]]\s*\(')


def validate_readonly_sql(sql: str) -> str:
    """
    校验待分析的 SQL 是否为单条只读查询，并返回规范化（去首尾空白与结尾分号）后的 SQL。

    规则：非空；去掉结尾的一个分号后不得再含分号（禁止多语句）；不得含 SQL 注释标记；
    必须以 SELECT/WITH 开头；不得包含写入/DDL/管理类关键字。

    Raises:
        ValueError: SQL 不满足只读分析的要求
    """
    if not isinstance(sql, str) or not sql.strip():
        raise ValueError("SQL 不能为空")
    normalized = sql.strip()
    if normalized.endswith(";"):
        normalized = normalized[:-1].rstrip()
    if ";" in normalized:
        raise ValueError("只允许分析单条语句")
    if "--" in normalized or "/*" in normalized or "#" in normalized:
        raise ValueError("SQL 中不允许包含注释")
    if not _READONLY_START_RE.match(normalized):
        raise ValueError("只允许分析 SELECT 查询")
    forbidden = _FORBIDDEN_SQL_RE.search(normalized)
    if forbidden:
        raise ValueError(f"只读分析不允许包含关键字: {forbidden.group(1).upper()}")
    if _QUOTED_CALL_RE.search(normalized):
        raise ValueError("只读分析不允许带引号的标识符作为函数调用")
    func = _FORBIDDEN_FUNC_RE.search(normalized)
    if func:
        raise ValueError("只读分析不允许调用有副作用的函数")
    return normalized


async def analyze_query_plan(
    sql: str,
    params: Optional[List[Any]] = None,
    conn_name: str = "default"
) -> Dict[str, Any]:
    """
    分析查询执行计划（只读，绝不执行传入的 SQL）

    仅接受单条 SELECT/WITH 查询（见 validate_readonly_sql），并只发出 EXPLAIN：
    - MySQL：``EXPLAIN``
    - PostgreSQL：``EXPLAIN (COSTS, VERBOSE, FORMAT JSON)``（不带 ANALYZE，ANALYZE 会真实执行语句）
    - SQLite：``EXPLAIN QUERY PLAN``（不再实际执行查询，因此不再返回 duration）

    Args:
        sql: 要分析的SQL查询
        params: 查询参数
        conn_name: 连接名称

    Returns:
        Dict[str, Any]: 查询执行计划分析；校验失败或出错时含 error 字段
    """
    try:
        sql = validate_readonly_sql(sql)
    except ValueError as e:
        return {"error": f"拒绝分析: {e}"}

    if not Tortoise._inited:
        return {"error": "Tortoise ORM未初始化"}

    dialect = None
    try:
        conn = Tortoise.get_connection(conn_name)
        dialect = conn.capabilities.dialect

        if dialect == "mysql":
            explain_result = await conn.execute_query_dict(f"EXPLAIN {sql}", params)
            
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
            explain_result = await conn.execute_query_dict(
                f"EXPLAIN (COSTS, VERBOSE, FORMAT JSON) {sql}", params
            )
            
            # PostgreSQL返回JSON格式的执行计划
            plan_json = explain_result[0]["QUERY PLAN"]
            if isinstance(plan_json, str):
                plan_json = json.loads(plan_json)
            
            return {
                "dialect": "postgres",
                "plan": plan_json,
                "recommendations": _generate_postgres_recommendations(plan_json)
            }
            
        elif dialect == "sqlite":
            explain_result = await conn.execute_query_dict(f"EXPLAIN QUERY PLAN {sql}", params)
            
            return {
                "dialect": "sqlite",
                "plan": explain_result,
                "recommendations": _generate_sqlite_recommendations(explain_result)
            }
            
        else:
            return {
                "dialect": dialect,
                "error": f"不支持的数据库类型: {dialect}"
            }
    except Exception as e:
        # 原始异常可能含 SQL 片段、库表结构或连接信息，只写服务端日志
        logger.error("查询计划分析失败 (conn=%s, dialect=%s): %r", conn_name, dialect, e)
        return {
            "error": "查询计划分析失败，请检查 SQL 与连接名称",
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
    根据PostgreSQL EXPLAIN结果生成优化建议

    Args:
        plan_json: PostgreSQL EXPLAIN (FORMAT JSON) 的结果

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
        root = plan_json[0]
        analyze_node(root.get("Plan", root))
    
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