#!/usr/bin/python3
# -*- encoding: utf-8 -*-

# @File    : do_pwn_template.py
# @Time    : 2021/04/02 21:15:43
# @Author  : Roderick Chan
# @Email   : ch22166@163.com
# @Desc    : pwn题本地调试、远程攻击脚本

'''
==========================================================================================
本脚本为pwn题所编写，利用click模块配置命令行参数，
能方便地进行本地调试和远程解题。
本地命令示例：
    python3 exp.py filename --tmux 1 --gdb-breakpoint 0x804802a --gdb-breakpoint printf
    python3 exp.py filename -t 1 -gb 0x804802a -gb printf
    python3 exp.py filename -t 1 -gs "x /12gx \$rebase(0x202080)" -sf 0 -pl "warn"
    即可开始本地调试,并且会断在地址或函数处。先启动tmux后，--tmux才会有效。

远程命令示例：
    python3 exp.py filename -i 127.0.0.1 -p 22164
    python3 exp.py filename -p 22164
    可以连接指定的IP和端口。目前在刷buuctf上的题，所以填了默认ip，只指定端口即可。

==========================================================================================
'''

from pwn import *
from LibcSearcher import LibcSearcher
import click
import sys
import os
import time
import functools

print(__doc__)

FILENAME = '#' # 要执行的文件名
DEBUG = 1 # 是否为调试模式
TMUX = 0 # 是否开启TMUX
GDB_BREAKPOINT = None # 当tmux开启的时候，断点的设置
GDB_SCRIPT = None # 当tmux开启的时候, gdb_script的设置，可以是任意有效的语句
IP = None # 远程连接的IP
PORT = None # 远程连接的端口
LOCAL_LOG = 1 # 本地LOG是否开启
PWN_LOG_LEVEL = 'debug' # pwntools的log级别设置
STOP_FUNCTION = 1 # STOP方法是否开启

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.command(context_settings=CONTEXT_SETTINGS, short_help='Do pwn!')
@click.argument('filename', nargs=1, type=str, required=0, default=None)
@click.option('-d', '--debug', default=True, type=bool, nargs=1, help='Excute program at local env or remote env. Default value: True.')
@click.option('-t', '--tmux', default=False, type=bool, nargs=1, help='Excute program at tmux or not. Default value: False.')
@click.option('-gb', '--gdb-breakpoint', default=[], type=str, multiple=True, help="Set a gdb breakpoint while tmux is enabled, is a hex address or '\$rebase' addr or a function name. Multiple setting supported. Default value:'[]'")
@click.option('-gs', '--gdb-script', default=None, type=str, help="Set a gdb script while tmux is enabled, the script will be passed to gdb and use '\\n' or ';' to split lines. Default value:None")
@click.option('-i', '--ip', default=None, type=str, nargs=1, help='The remote ip addr. Default value: None.')
@click.option('-p', '--port', default=None, type=int, nargs=1, help='The remote port. Default value: None.')
@click.option('-ll', '--local-log', default=True, type=bool, nargs=1, help='Set local log enabled or not. Default value: True.')
@click.option('-pl', '--pwn-log', type=click.Choice(['debug', 'info', 'warn', 'error', 'notset']), nargs=1, default='debug', help='Set pwntools log level. Default value: debug.')
@click.option('-sf', '--stop-function', default=True, type=bool, nargs=1, help='Set stop function enabled or not. Default value: True.')
def parse_command_args(filename, debug, tmux, gdb_breakpoint, gdb_script,
                       ip, port, local_log, pwn_log, stop_function):
    '''FILENAME: The filename of current directory to pwn'''
    global FILENAME, DEBUG, TMUX, GDB_BREAKPOINT, GDB_SCRIPT, IP, PORT, LOCAL_LOG, PWN_LOG_LEVEL, STOP_FUNCTION
    # assign
    FILENAME = filename
    DEBUG = debug
    TMUX = tmux
    GDB_BREAKPOINT = gdb_breakpoint
    GDB_SCRIPT = gdb_script
    IP = ip
    PORT = port
    LOCAL_LOG = local_log
    PWN_LOG_LEVEL = pwn_log
    STOP_FUNCTION = stop_function

    # change
    if PORT: # 远程下这些是需要关闭的
        DEBUG = 0
        TMUX = 0
        STOP_FUNCTION = 0
        GDB_BREAKPOINT = None
        GDB_SCRIPT = None
        if IP is None:
            IP = 'node3.buuoj.cn'
    
    if DEBUG:
        IP = None
        PORT = None
    
    # assert
    assert not (FILENAME is None and PORT is None), 'para error'
    assert not (FILENAME is None and DEBUG == 1), 'para error'
    assert not (PORT is not None and DEBUG == 1), 'para error'
    assert not (DEBUG == 0 and TMUX == 1), 'para error'
    
    # print
    click.echo('=' * 50)
    click.echo(' [+] Args info:\n')
    if FILENAME:
        click.echo('  filename: %s' % FILENAME)
    click.echo('  debug enabled: %d' % DEBUG)
    click.echo('  tmux enabled: %d' % TMUX)
    if GDB_BREAKPOINT:
        click.echo('  gdb breakpoint: {}'.format(GDB_BREAKPOINT))
	if GDB_SCRIPT:
		click.echo("  gdb script: {}".format(GDB_SCRIPT))
    if IP:
        click.echo('  remote ip: %s' % IP)
    if PORT:
        click.echo('  remote port: %d' % PORT)
    click.echo('  local log enabled: %d' % LOCAL_LOG)
    click.echo('  pwn log_level: %s' % PWN_LOG_LEVEL)
    click.echo('  stop function enabled: %d' % STOP_FUNCTION)
    click.echo('=' * 50)
    

parse_command_args.main(standalone_mode=False)

# 退出条件，只要参数有 -h 或 --help就退出
if len(sys.argv) > 1:
    for arg in sys.argv:
        if '-h' == arg or '--help' == arg:
            sys.exit(0)

if DEBUG:
    io = process('{}'.format(FILENAME))
else:
    io = remote(IP, PORT)

if TMUX:
    context.update(terminal=['tmux', 'splitw', '-h'])
    tmp_all_gdb = ""
    if GDB_BREAKPOINT is not None or len(GDB_BREAKPOINT) > 0:
        # 解析每一条gdb-breakpoint
        for gb in GDB_BREAKPOINT:
            if gb.startswith('0x') or gb.startswith('$rebase('):
                tmp_all_gdb += "b *{}\n".format(gb) # 带上*
            else: # 传入函数
                tmp_all_gdb += "b {}\n".format(gb) # 不带*
    if GDB_SCRIPT is not None:
        tmp_all_gdb += GDB_SCRIPT.replace("\\n", "\n").replace(";", "\n") + "\n"
    tmp_all_gdb += "c\n"
    gdb.attach(io, gdbscript=tmp_all_gdb)


if FILENAME:
    cur_elf = ELF('{}'.format(FILENAME))
    print('[+] libc used ===> {}'.format(cur_elf.libc))



def LOG_ADDR(addr_name:str, addr:int):
    if LOCAL_LOG:
        log.success("{} ===> {}".format(addr_name, hex(addr)))
    else:
        pass


def LOG_ADDR_EX(addr_name:str):
    '''
    存储地址的变量名，字符串
    如：a = 0xdeadbeef 
    调用: LOG_ADDR_EX('a')
    
    '''
    if LOCAL_LOG:
        # 利用eval函数, 首先检索一下
        if addr_name in globals() or addr_name in vars():
            tmp_var = eval(addr_name)
            log.success("{} ===> {}".format(addr_name, hex(tmp_var)))
        else:
            log.warn("No variable named: '" + addr_name + "'")
    else:
        pass
    


def STOP():
    if not STOP_FUNCTION:
        return
    print("stop...{}  {}".format(sys._getframe().f_lineno, proc.pidof(io)))
    pause()


############### 定义一些偏函数 ###################

int16 = functools.partial(int, base=16)

#################### END ########################


############### 定义一些装饰器函数 ###############

def time_count(func):
    '''
    装饰器：统计函数运行时间
    '''
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        print('=' * 50)
        print('function #{}# start...'.format(func.__name__))
        start = time.time()
        res = func(*args, **kwargs)
        end = time.time()
        print('function #{}# end...execute time: {} s / {} min'.format(func.__name__, end - start, (end - start) / 60))
        return res
    return wrapper


def sleep_call(second:int=1, mod:int=1):
    """
    装饰器：在调用函数前后线程先睡眠指定秒数
    
    Args:
        second: 休眠秒数
        mod: 0 不休眠; 1 为调用前休眠; 2 为调用后休眠; 3 为前后均修眠
    """
    if mod > 3 or mod < 0:
        mod = 1
    def wrapper1(func):
        @functools.wraps(func)
        def wrapper2(*args, **kwargs):
            if mod & 1:
                time.sleep(second)
            res = func(*args, **kwargs)
            if mod & 2:
                time.sleep(second)
            return res
        return wrapper2
    return wrapper1
    
#################### END ########################

context.update(log_level=PWN_LOG_LEVEL)

# 一般需要带上文件，可注释改行语句
assert FILENAME is not None, 'give me a file!'
##################################################
##############以下为攻击代码#######################
##################################################