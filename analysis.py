import json
import time
from datetime import datetime
from typing import Dict, List, Tuple
import os
import glob

# 检查并安装必要的依赖
try:
    import pandas as pd
except ImportError:
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pandas"])
    import pandas as pd

try:
    from haralyzer import HarParser, HarPage
except ImportError:
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "haralyzer"])
    from haralyzer import HarParser, HarPage


class HARPerformanceAnalyzer:
    def __init__(self, har_file_path: str):
        """初始化分析器,加载HAR文件"""       
        self.har_file = har_file_path       
        self.har_data = self._load_har_file()       
        try:
            self.parser = HarParser(self.har_data)       
            self.pages = self.parser.pages  # 页面级数据(含导航时序)       
            self.entries = self.parser.har_data["log"]["entries"]  # 所有网络请求
        except Exception as e:
            print(f"使用haralyzer解析失败: {str(e)}")
            print("尝试直接解析HAR数据...")
            self.entries = self.har_data["log"]["entries"]
            self.pages = []
        
    def _load_har_file(self) -> Dict:
        """加载HAR文件,返回JSON格式数据"""        
        try:
            with open(self.har_file, "r", encoding="utf-8") as f:                
                data = json.load(f)
                
            # 验证HAR格式
            if "log" not in data or "entries" not in data["log"]:
                raise ValueError("HAR文件格式不正确，缺少必要的'log'或'entries'字段")
                
            return data        
        except Exception as e:
            raise ValueError(f"HAR文件加载失败: {str(e)}")
        
    def _get_resource_type(self, url: str, content_type: str) -> str:
        """根据URL和Content-Type判断资源类型"""
        if not content_type:
            content_type = ""
        if "text/html" in content_type:
            return "HTML"        
        elif "text/css" in content_type:
            return "CSS"
        elif "application/javascript" in content_type or "text/javascript" in content_type:
            return "JS"        
        elif "image/" in content_type:
            return "图片"
        elif "font/" in content_type or "application/font" in content_type:
            return "字体"
        elif "application/json" in content_type or url.endswith(".json"):
            return "JSON接口"
        elif "video/" in content_type:
            return "视频"
        else:
            # 根据文件扩展名判断
            if url.lower().endswith(('.js', '.jsx', '.ts', '.tsx')):
                return "JS"
            elif url.lower().endswith(('.css')):
                return "CSS"
            elif url.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp')):
                return "图片"
            elif url.lower().endswith(('.woff', '.woff2', '.ttf', '.eot')):
                return "字体"
            else:
                return "其他"
            
    def analyze_request_details(self) -> pd.DataFrame:
        """分析每个请求的详细性能指标"""        
        request_list = []        
        for idx, entry in enumerate(self.entries, 1):            
            request = entry.get("request", {})
            response = entry.get("response", {})
            timing = entry.get("timings", {})
            
            # 获取URL和域名
            url = request.get("url", "")
            try:
                if "//" in url:
                    domain = url.split("//")[-1].split("/")[0]  # 提取域名
                else:
                    domain = "unknown"
            except:
                domain = "unknown"
            
            # 核心耗时指标(处理-1为无数据的情况)
            dns_time = timing.get("dns", -1) if timing.get("dns", -1) != -1 else 0            
            tcp_time = timing.get("connect", -1) if timing.get("connect", -1) != -1 else 0            
            ssl_time = timing.get("ssl", -1) if timing.get("ssl", -1) != -1 else 0            
            send_time = timing.get("send", -1) if timing.get("send", -1) != -1 else 0            
            wait_time = timing.get("wait", -1) if timing.get("wait", -1) != -1 else 0  # 服务器响应等待时间            
            receive_time = timing.get("receive", -1) if timing.get("receive", -1) != -1 else 0            
            total_time = entry.get("time", 0)  # 总耗时
            
            # 资源大小(headersSize + bodySize,单位:KB)            
            headers_size = response.get("headersSize", 0)
            body_size = response.get("bodySize", 0)
            total_size = (headers_size + body_size) / 1024 if (headers_size + body_size) > 0 else 0
            
            # 慢资源标记(阈值:500ms,可调整)
            is_slow = "是" if total_time > 500 else "否"
            
            request_list.append({                
                "序号": idx,                
                "资源URL": url,                
                "资源类型": self._get_resource_type(url, response.get("content", {}).get("mimeType", "")),                
                "请求方法": request.get("method", ""),                
                "状态码": response.get("status", 0),                
                "域名": domain,                
                "总耗时(ms)": round(total_time, 2),                
                "DNS解析(ms)": round(dns_time, 2),                
                "TCP连接(ms)": round(tcp_time, 2),                
                "SSL握手(ms)": round(ssl_time, 2),                
                "请求发送(ms)": round(send_time, 2),                
                "服务器等待(ms)": round(wait_time, 2),                
                "响应接收(ms)": round(receive_time, 2),                
                "资源大小(KB)": round(total_size, 2),                
                "慢资源标记": is_slow,                
                "是否错误请求": "是" if response.get("status", 0) >= 400 else "否"            
            })
        
        return pd.DataFrame(request_list)
        
    def analyze_page_timings(self) -> Dict:
        """分析页面级核心性能指标(基于Navigation Timing)"""
        # 如果无法使用haralyzer，尝试直接从entries中获取信息
        if not self.pages:            
            # 尝试从entries中获取基本信息
            if self.entries:
                first_entry = self.entries[0]
                url = first_entry.get("request", {}).get("url", "Unknown URL")
                return {
                    "页面URL": url,
                    "导航开始时间": "不可用",
                    "DOM就绪时间(ms)": "不可用",
                    "页面完全加载时间(ms)": "不可用",
                    "首次内容绘制FCP(ms)": "不可用",
                    "首屏加载时间(ms)": "不可用"
                }
            else:
                return {
                    "提示": "未获取到页面时序数据"
                }
        
        try:
            page = self.pages[0]  # 首个页面(单页面应用通常只有1个)        
            timings = page.timings  # 页面导航时序(单位:ms)

            # 关键指标计算
            navigation_start = timings.get("navigationStart", 0)        
            dom_content_loaded = (timings.get("domContentLoadedEventEnd", 0) - navigation_start) if navigation_start > 0 else 0
            load_event = (timings.get("loadEventEnd", 0) - navigation_start) if navigation_start > 0 else 0
            
            # 尝试获取FCP时间
            try:
                first_contentful_paint = page.pageTimings.get("_firstContentfulPaint", 0)
            except:
                first_contentful_paint = 0

            return {            
                "页面URL": page.url,            
                "导航开始时间": datetime.fromtimestamp(navigation_start/1000).strftime("%Y-%m-%d %H:%M:%S") if navigation_start and navigation_start > 0 else "无",            
                "DOM就绪时间(ms)": round(dom_content_loaded, 2) if dom_content_loaded >= 0 else 0,            
                "页面完全加载时间(ms)": round(load_event, 2) if load_event >= 0 else 0,            
                "首次内容绘制FCP(ms)": round(first_contentful_paint, 2) if first_contentful_paint and first_contentful_paint > 0 else "未捕获",            
                "首屏加载时间(ms)": round(first_contentful_paint + 300, 2) if first_contentful_paint and first_contentful_paint > 0 else "未捕获"  # 经验值补充       
            }
        except Exception as e:
            print(f"页面时序分析失败: {str(e)}")
            # 如果haralyzer分析失败，使用基础信息
            if self.entries:
                first_entry = self.entries[0]
                url = first_entry.get("request", {}).get("url", "Unknown URL")
                return {
                    "页面URL": url,
                    "导航开始时间": "不可用",
                    "DOM就绪时间(ms)": "不可用",
                    "页面完全加载时间(ms)": "不可用",
                    "首次内容绘制FCP(ms)": "不可用",
                    "首屏加载时间(ms)": "不可用"
                }
            else:
                return {"提示": "未获取到页面时序数据"}
    
    def generate_summary(self, request_df: pd.DataFrame, page_timings: Dict) -> pd.DataFrame:
        """生成性能统计汇总"""        
        total_requests = len(request_df)        
        slow_requests = len(request_df[request_df["慢资源标记"] == "是"])        
        error_requests = len(request_df[request_df["是否错误请求"] == "是"])        
        avg_total_time = request_df["总耗时(ms)"].mean() if len(request_df) > 0 else 0
        
        # 资源类型分布        
        resource_dist = request_df["资源类型"].value_counts().to_dict()        
        resource_dist_str = "; ".join([f"{k}: {v}个" for k, v in resource_dist.items()]) if resource_dist else "无数据"
        
        # 域名分布        
        domain_dist = request_df["域名"].value_counts().to_dict()        
        domain_dist_str = "; ".join([f"{k}: {v}个" for k, v in domain_dist.items()]) if domain_dist else "无数据"
        
        # 耗时Top3资源        
        top3_slow = request_df.nlargest(3, "总耗时(ms)")["资源URL"].tolist()        
        top3_slow_str = "; ".join([f"{url.split('?')[0][-50:]}" for url in top3_slow]) if top3_slow else "无数据"

        summary_data = {            
            "统计指标": [                
                "总请求数", 
                "慢资源数(>500ms)", 
                "错误请求数(4xx/5xx)", 
                "平均请求耗时(ms)",                
                "页面完全加载时间(ms)", 
                "DOM就绪时间(ms)", 
                "首次内容绘制FCP(ms)",                
                "资源类型分布", 
                "域名分布", 
                "耗时Top3资源"            
            ],            
            "数值": [                
                total_requests, 
                slow_requests, 
                error_requests, 
                round(avg_total_time, 2),                
                page_timings.get("页面完全加载时间(ms)", 0), 
                page_timings.get("DOM就绪时间(ms)", 0), 
                page_timings.get("首次内容绘制FCP(ms)", "未捕获"), 
                resource_dist_str, 
                domain_dist_str, 
                top3_slow_str            
            ]       
        }
                
        return pd.DataFrame(summary_data)
    
    def identify_bottlenecks(self, request_df: pd.DataFrame, summary: pd.DataFrame) -> pd.DataFrame:        
        """识别性能瓶颈并给出优化建议"""        
        bottlenecks = []        
        summary_dict = dict(zip(summary["统计指标"], summary["数值"]))        
        
        # 1. 慢资源瓶颈        
        slow_count = summary_dict.get("慢资源数(>500ms)", 0)
        if isinstance(slow_count, str):
            slow_count = 0
        elif slow_count > 0:            
            bottlenecks.append({                
                "瓶颈类型": "慢资源过多",                
                "描述": f"共存在{slow_count}个加载耗时超过500ms的资源,影响页面加载速度",                
                "优化建议": "1. 压缩图片资源(使用TinyPNG);2. 对JS/CSS进行代码分割和懒加载;3. 启用CDN加速静态资源;4. 优化服务器响应时间"
            })
        
        # 2. 请求数过多
        total_requests = summary_dict.get("总请求数", 0)
        if isinstance(total_requests, str):
            total_requests = 0
        if total_requests > 80:            
            bottlenecks.append({                
                "瓶颈类型": "请求数过多",                
                "描述": f"页面总请求数{total_requests}个,超过合理阈值(80个),增加网络开销",                
                "优化建议": "1. 合并JS/CSS文件(使用Webpack打包);2. 使用图片雪碧图(Sprite);3. 减少第三方库依赖,按需引入"            
            })
            
        # 3. 错误请求
        error_count = summary_dict.get("错误请求数(4xx/5xx)", 0)
        if isinstance(error_count, str):
            error_count = 0
        if error_count > 0:      
            bottlenecks.append({       
                "瓶颈类型": "错误请求",       
                "描述": f"存在{error_count}个错误请求,可能导致功能异常或资源加载失败",       
                "优化建议": "1. 检查资源URL是否正确;2. 排查接口服务状态;3. 修复4xx(资源不存在)/5xx(服务器错误)问题"      
            })
            
        # 4. 平均耗时过高
        avg_time = summary_dict.get("平均请求耗时(ms)", 0)
        if isinstance(avg_time, str):
            avg_time = 0
        if avg_time > 300:      
            bottlenecks.append({       
                "瓶颈类型": "平均请求耗时过高",       
                "描述": f"平均请求耗时{avg_time}ms,超过合理阈值(300ms)",       
                "优化建议": "1. 优化数据库查询(添加索引);2. 启用服务器缓存(Redis);3. 升级服务器带宽;4. 采用HTTP/2协议"      
            })
            
        # 5. FCP过慢(用户体验核心指标)
        fcp = summary_dict.get("首次内容绘制FCP(ms)", "未捕获")
        if fcp != "未捕获" and isinstance(fcp, (int, float)) and fcp > 1800:      
            bottlenecks.append({       
                "瓶颈类型": "首次内容绘制(FCP)过慢",       
                "描述": f"FCP耗时{fcp}ms,超过优秀阈值(1800ms),影响用户首屏体验",       
                "优化建议": "1. 内联首屏关键CSS;2. 预加载核心HTML/JS;3. 减少首屏非必要资源;4. 优化服务器响应速度"      
            })   
            
        if not bottlenecks:      
            bottlenecks.append({       
                "瓶颈类型": "无明显性能瓶颈",       
                "描述": "页面性能表现良好,各项指标在合理范围内",       
                "优化建议": "1. 持续监控资源加载状态;2. 定期清理冗余资源;3. 跟进HTTP/3等新协议优化"      
            })   
        
        return pd.DataFrame(bottlenecks) 
        
    def export_to_excel(self, output_path: str = None):   
        """导出所有分析结果到Excel(多工作表)"""
        try:
            print(f"开始分析HAR文件: {self.har_file}")
            # 执行所有分析
            request_df = self.analyze_request_details()
            print(f"分析了 {len(request_df)} 个请求")
            
            page_timings = self.analyze_page_timings()
            print(f"页面时序分析完成")
            
            summary_df = self.generate_summary(request_df, page_timings)
            print(f"生成统计汇总")
            
            bottleneck_df = self.identify_bottlenecks(request_df, summary_df)
            print(f"完成瓶颈分析")
            
            # 生成输出路径   
            if not output_path:      
                # 从文件名生成输出路径
                base_name = os.path.splitext(os.path.basename(self.har_file))[0]
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")      
                output_path = f"{base_name}_性能分析报告_{timestamp}.xlsx"   
            
            # 使用ExcelWriter创建多工作表   
            with pd.ExcelWriter(output_path, engine="openpyxl") as writer:     
                # 工作表1:请求详细列表      
                request_df.to_excel(writer, sheet_name="请求详细列表", index=False)     
                
                # 工作表2:页面核心时序      
                page_timings_df = pd.DataFrame([page_timings])
                page_timings_df.to_excel(writer, sheet_name="页面核心时序", index=False)     
                
                # 工作表3:统计汇总      
                summary_df.to_excel(writer, sheet_name="统计汇总", index=False)     
                
                # 工作表4:性能瓶颈分析      
                bottleneck_df.to_excel(writer, sheet_name="性能瓶颈与优化建议", index=False)   
            
            print(f"Excel报告已生成: {output_path}")
            return output_path
        except Exception as e:
            print(f"导出Excel报告失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return None


def batch_analyze_har_files():
    """批量分析HAR目录下的所有HAR文件"""
    har_dir = "har"
    
    # 检查har目录是否存在
    if not os.path.exists(har_dir):
        print(f"错误: 目录 '{har_dir}' 不存在")
        print(f"请创建 '{har_dir}' 目录并将HAR文件放入其中")
        return
    
    # 递归查找所有 .har 文件（包括子目录）
    har_files = glob.glob(os.path.join(har_dir, "**", "*.har"), recursive=True)
    
    # 去重（虽然通常不需要，但保险起见）
    har_files = list(set(os.path.abspath(f) for f in har_files))
    har_files.sort()  # 保持顺序可读
    
    if not har_files:
        print(f"在 '{har_dir}' 目录及其子目录中未找到任何HAR文件")
        print("请确保HAR文件已放入har目录或其子目录中")
        return
    
    print(f"找到 {len(har_files)} 个HAR文件:")
    for i, file in enumerate(har_files, 1):
        print(f"  {i}. {file}")
    
    print("\n开始批量分析...")
    
    results = []
    failed_files = []
    
    for har_file in har_files:
        try:
            print(f"\n正在分析: {har_file}")
            analyzer = HARPerformanceAnalyzer(har_file)
            result_path = analyzer.export_to_excel()
            
            if result_path:
                results.append((har_file, result_path))
                print(f"✓ 分析完成: {result_path}")
            else:
                failed_files.append(har_file)
                print(f"✗ 分析失败: {har_file}")
                
        except Exception as e:
            failed_files.append(har_file)
            print(f"✗ 分析失败 {har_file}: {str(e)}")
            import traceback
            traceback.print_exc()
    
    print(f"\n批量分析完成!")
    print(f"成功分析: {len(results)} 个文件")
    print(f"失败: {len(failed_files)} 个文件")
    
    if results:
        print("\n成功生成的报告:")
        for original, report in results:
            print(f"  - {original} -> {report}")
    
    if failed_files:
        print("\n分析失败的文件:")
        for file in failed_files:
            print(f"  - {file}")


if __name__ == "__main__":
    batch_analyze_har_files()



