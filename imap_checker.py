import os
import sys
import re
import socket
import imaplib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# 保证 Windows 控制台输出 UTF-8 字符正常
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# 常见邮箱 IMAP 服务器与端口配置
IMAP_SERVERS = {
    "gmail.com": ("imap.gmail.com", 993),
    "googlemail.com": ("imap.gmail.com", 993),
    "outlook.com": ("outlook.office365.com", 993),
    "hotmail.com": ("outlook.office365.com", 993),
    "live.com": ("outlook.office365.com", 993),
    "yahoo.com": ("imap.mail.yahoo.com", 993),
    "icloud.com": ("imap.mail.me.com", 993),
    "qq.com": ("imap.qq.com", 993),
    "163.com": ("imap.163.com", 993),
}

def get_imap_server(email):
    domain = email.split("@")[-1].lower() if "@" in email else ""
    return IMAP_SERVERS.get(domain, ("imap.gmail.com", 993))


def verify_imap_account(email, password, timeout=8):
    """
    测试单个邮箱的 IMAP 互通性与登录凭证
    """
    host, port = get_imap_server(email)
    try:
        mail = imaplib.IMAP4_SSL(host, port, timeout=timeout)
        status, _ = mail.login(email, password)
        try:
            mail.logout()
        except Exception:
            pass
        return True, "登录成功"
    except imaplib.IMAP4.error as e:
        err_msg = str(e)
        if "Invalid credentials" in err_msg or "AUTHENTICATIONFAILED" in err_msg:
            return False, "凭证错误 (密码错误/应用密码失效)"
        elif "WebLoginRequired" in err_msg:
            return False, "需要网页验证/二次验证"
        elif "Application-specific password required" in err_msg:
            return False, "需要应用专用密码"
        return False, f"登录拒绝: {err_msg[:40]}"
    except (socket.timeout, TimeoutError):
        return False, "连接超时"
    except Exception as e:
        return False, f"网络/SSL异常: {str(e)[:40]}"


def scan_available_txt_files(base_dir):
    """
    扫描当前目录及子目录下的所有待检测 txt 文件（自动排除输出文件）
    """
    txt_files = []
    seen_paths = set()

    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if not d.startswith(".") and not d.startswith("_")]
        for f in files:
            if f.endswith(".txt") and not f.startswith("valid_"):
                full_path = os.path.join(root, f)
                norm_path = os.path.normcase(os.path.abspath(full_path))
                if norm_path not in seen_paths:
                    seen_paths.add(norm_path)
                    rel_path = os.path.relpath(full_path, base_dir)
                    txt_files.append((rel_path, full_path))

    return txt_files


def select_input_files(base_dir, cli_file=None):
    """
    让用户交互式选择需要检查的文件（单选、多选、合并、或自定义拖拽）
    """
    if cli_file:
        cleaned = cli_file.strip('\'"')
        if os.path.exists(cleaned):
            return [cleaned]
        else:
            print(f"[错误] 指定的文件不存在: {cleaned}")
            return []

    available = scan_available_txt_files(base_dir)

    if not available:
        try:
            custom_path = input("未扫描到 txt 文件，请输入或拖拽待检查的文件路径: ").strip('\'"')
        except (EOFError, KeyboardInterrupt):
            return []
        if os.path.exists(custom_path):
            return [custom_path]
        return []

    print("\n" + "=" * 65)
    print(" [文件列表] 扫描到以下待检测文本文件：")
    print("=" * 65)
    for idx, (rel, _) in enumerate(available, 1):
        print(f"  [{idx}] {rel}")
    print("  [A] 全部合并检查 (自动去重)")
    print("  [C] 自定义输入 / 鼠标直接拖拽文件到这里")
    print("=" * 65)

    try:
        user_choice = input("请选择要检查的文件编号 [支持多选如 1,2，默认 A 全部合并]: ").strip().upper()
    except (EOFError, KeyboardInterrupt):
        user_choice = "A"

    if not user_choice or user_choice == "A":
        return [f[1] for f in available]

    if user_choice == "C":
        try:
            custom_path = input("请输入或拖拽 txt 文件到此处: ").strip('\'"')
        except (EOFError, KeyboardInterrupt):
            return []
        if os.path.exists(custom_path):
            return [custom_path]
        else:
            print(f"[错误] 路径不存在: {custom_path}")
            return []

    # 判断是否直接拖拽/输入了文件路径
    cleaned = user_choice.strip('\'"')
    if os.path.exists(cleaned):
        return [cleaned]

    # 支持多选，如 "1, 2" 或单个 "1"
    selected = []
    parts = [p.strip() for p in user_choice.replace("，", ",").split(",") if p.strip()]
    for p in parts:
        if p.isdigit() and 1 <= int(p) <= len(available):
            selected.append(available[int(p) - 1][1])

    if selected:
        return selected

    print("[提示] 输入未识别，默认采用 [A] 全部合并检查。")
    return [f[1] for f in available]


def parse_accounts(file_paths):
    """
    从一个或多个文本文件中提取账号密码并自动去重
    """
    if isinstance(file_paths, str):
        file_paths = [file_paths]

    accounts = []
    seen = set()
    email_pattern = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")

    for file_path in file_paths:
        if not os.path.exists(file_path):
            continue
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue

                parts = line.split(":", 1)
                email, password = parts[0].strip(), parts[1].strip()

                if email_pattern.match(email) and email not in seen:
                    seen.add(email)
                    accounts.append((email, password))

    return accounts


def load_existing_valid(valid_txt_path):
    """
    读取已验证通过的历史有效账号
    """
    existing_valid = []
    seen = set()
    if os.path.exists(valid_txt_path):
        with open(valid_txt_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    email, pwd = line.split(":", 1)
                    email = email.strip()
                    if email not in seen:
                        seen.add(email)
                        existing_valid.append((email, pwd.strip()))
    return existing_valid, seen


def run_batch_check(
    cli_file=None,
    output_txt="valid_accounts.txt",
    output_py="valid_accounts.py",
    max_workers=10,
    timeout=8
):
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. 选择待检查文件
    selected_files = select_input_files(base_dir, cli_file)
    if not selected_files:
        print("[退出] 未选择任何有效文件。")
        return

    out_txt_path = os.path.join(base_dir, output_txt)
    out_py_path = os.path.join(base_dir, output_py)

    print("\n" + "=" * 65)
    print("选中的待检测文件列表：")
    for f in selected_files:
        print(f" -> {os.path.relpath(f, base_dir)}")
    print(f"有效账号保存目标: {out_txt_path}")
    print("=" * 65)

    # 2. 读取已有通过记录，避免重复检查和丢失
    existing_valid, existing_seen = load_existing_valid(out_txt_path)
    if existing_seen:
        print(f"[历史记录] 发现已有 {len(existing_seen)} 个有效账号，将自动跳过已验证通过的账号！")

    # 3. 解析所有选中的文件
    all_accounts = parse_accounts(selected_files)
    total_parsed = len(all_accounts)

    # 过滤掉已经验证过的有效账号
    pending_accounts = [acc for acc in all_accounts if acc[0] not in existing_seen]
    skip_count = total_parsed - len(pending_accounts)

    print(f"[解析统计] 提取到去重账号: {total_parsed} 个 (已跳过历史通过账号: {skip_count} 个)")
    print(f"[待测账号] 实际待检测: {len(pending_accounts)} 个")
    print(f"[运行配置] 并发线程: {max_workers}，连接超时: {timeout} 秒\n")

    if not pending_accounts:
        print("[完成] 所有账号均已在有效列表中，无需重复检测！")
        return

    lock = threading.Lock()
    checked_count = 0
    new_valid_count = 0
    all_valid_accounts = list(existing_valid)

    # 4. 多线程并发批量测试
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_acc = {
            executor.submit(verify_imap_account, email, pwd, timeout): (email, pwd)
            for email, pwd in pending_accounts
        }

        for future in as_completed(future_to_acc):
            email, pwd = future_to_acc[future]
            try:
                is_valid, reason = future.result()
            except Exception as e:
                is_valid, reason = False, str(e)

            with lock:
                checked_count += 1
                if is_valid:
                    new_valid_count += 1
                    all_valid_accounts.append((email, pwd))
                    # 实时追加写入有效文本
                    with open(out_txt_path, "a", encoding="utf-8") as f:
                        f.write(f"{email}:{pwd}\n")
                    print(f"[{checked_count}/{len(pending_accounts)}] [OK 通过] {email}")
                else:
                    print(f"[{checked_count}/{len(pending_accounts)}] [FAIL 失败] {email} ({reason})")

    # 5. 生成 Python 数组格式代码文件
    code_lines = ["account_list = [\n"]
    for email, pwd in all_valid_accounts:
        code_lines.append(f'    ("{email}", "{pwd}"),\n')
    code_lines.append("]\n")

    with open(out_py_path, "w", encoding="utf-8") as f:
        f.writelines(code_lines)

    # 6. 最终统计汇报
    print("\n" + "=" * 65)
    print(" [任务结束] 检查已完成！")
    print(f"本次实际检测: {len(pending_accounts)} 个账号")
    print(f"本次新通过  : {new_valid_count} 个")
    print(f"总计有效账号: {len(all_valid_accounts)} 个 (包含历史记录)")
    print(f"文本列表路径: {out_txt_path}")
    print(f"Python 格式 : {out_py_path}")
    print("=" * 65)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IMAP 邮箱凭证互通性批量检查工具")
    parser.add_argument("-f", "--file", help="指定待检查的文本路径（支持直接传入或拖拽）", default=None)
    parser.add_argument("-w", "--workers", help="并发线程数 (默认 10)", type=int, default=10)
    parser.add_argument("-t", "--timeout", help="单次超时时间(秒) (默认 8)", type=int, default=8)
    args = parser.parse_args()

    run_batch_check(cli_file=args.file, max_workers=args.workers, timeout=args.timeout)
