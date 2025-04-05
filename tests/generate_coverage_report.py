#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
测试覆盖率报告生成工具

生成详细的测试覆盖率报告，并提供命令行参数来控制报告格式和输出位置
"""

import os
import sys
import argparse
import subprocess
from datetime import datetime


def generate_coverage_report(format_type='term', output_dir='coverage_reports'):
    """
    生成测试覆盖率报告
    
    Args:
        format_type: 报告格式（term, html, xml）
        output_dir: 输出目录
    """
    # 确保输出目录存在
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 获取时间戳
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # 执行pytest命令
    if format_type == 'term':
        # 终端输出
        cmd = ['pytest', '--cov=app', 'tests/', '-v']
    elif format_type == 'html':
        # HTML报告
        html_dir = os.path.join(output_dir, f'html_report_{timestamp}')
        if not os.path.exists(html_dir):
            os.makedirs(html_dir)
        cmd = ['pytest', '--cov=app', 'tests/', '--cov-report', f'html:{html_dir}']
    elif format_type == 'xml':
        # XML报告
        xml_file = os.path.join(output_dir, f'coverage_{timestamp}.xml')
        cmd = ['pytest', '--cov=app', 'tests/', '--cov-report', f'xml:{xml_file}']
    else:
        print(f"不支持的报告格式: {format_type}")
        return False
    
    # 执行命令
    try:
        result = subprocess.run(cmd, check=True)
        print(f"测试覆盖率报告已生成 ({format_type})")
        
        if format_type == 'html':
            print(f"HTML报告路径: {html_dir}")
        elif format_type == 'xml':
            print(f"XML报告路径: {xml_file}")
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"生成覆盖率报告时出错: {e}")
        return False


def main():
    """主函数，处理命令行参数"""
    parser = argparse.ArgumentParser(description='生成测试覆盖率报告')
    parser.add_argument(
        '--format', 
        choices=['term', 'html', 'xml', 'all'], 
        default='term',
        help='报告格式 (term=终端输出, html=HTML报告, xml=XML报告, all=所有格式)'
    )
    parser.add_argument(
        '--output-dir', 
        default='coverage_reports',
        help='报告输出目录'
    )
    
    args = parser.parse_args()
    
    if args.format == 'all':
        # 生成所有格式的报告
        formats = ['term', 'html', 'xml']
        for fmt in formats:
            generate_coverage_report(fmt, args.output_dir)
    else:
        # 生成指定格式的报告
        generate_coverage_report(args.format, args.output_dir)


if __name__ == '__main__':
    main() 