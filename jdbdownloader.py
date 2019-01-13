#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import os
import ftplib
import requests
import logging
import threadpool
import math
import time

from collections import namedtuple

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
logging.basicConfig(filename='symantec.log', level=logging.INFO, format=LOG_FORMAT, datefmt=DATE_FORMAT)

JdbFile = namedtuple('JdbFile', 'url name size md5')


class ThreadDownloadException(Exception):
    """thrown by t_download while an error occured."""



def get_target(page="http://www.symantec.com/avcenter/download/pages/CS-SAVCE.html"):
    # page给出的MD5值
    md5_pattern = re.compile(r"[A-F0-9]{32}")
    # page中的jdb文件下载地址
    url_pattern = re.compile(r"http://definitions\.symantec\.com/defs/jdb/vd[0-9]{6}\.jdb")
    try:
        resp = requests.get(url=page)
        # 匹配到jdb文件的下载地址url
        url = url_pattern.findall(resp.text)[0]
        # 获取jdp文件下载页的头部信息，只需少量网络流量即可获得概要信息
        file_resp = requests.head(url=url)
        filesize = file_resp.headers["Content-Length"]
        if 200 == resp.status_code and 200 == file_resp.status_code:
            # 匹配到jdb文件的md5值
            md5 = md5_pattern.findall(resp.text)[2]
            # jdb文件名
            filename = url.split("/")[-1]
            # 返回jdb文件的下载信息
            return JdbFile(url=url, name=filename, size=int(filesize), md5=md5)
        else:
            logging.warn("Fail to open download page")
    except:
        logging.warn("Fail to open download page")
        return None


def t_download(url, filename, start, end):
    headers = {
        "Range": "bytes=%d-%d" % (start, end)
    }
    try:
        resp = requests.get(url=url, headers=headers, stream=True)
        # 打开已存在的文件
        with open(filename, "r+") as fd:
            fd.seek(start, 0)
            # 一块一块的遍历要下载的内容，写入本地jdb文件
            for chunk in resp.iter_content(chunk_size=1024):
                if chunk:
                    fd.write(chunk)
    except:
        raise ThreadDownloadException


def download(target):
    print "start download"
    target = get_target()
    url = target.url
    filename = target.name
    filesize = target.size
    chunksize = 1 * 1024 * 1024
    chunkcnt = int(math.ceil(filesize * 1.0 / chunksize))
    arg_list = []
    for i in range(chunkcnt):
        offset = chunksize * i
        len = min(chunksize, filesize - offset)
        start = offset
        end = offset + len
        chunkdic = {}
        chunkdic['url'] = url
        chunkdic['filename'] = filename
        chunkdic['start'] = start
        chunkdic['end'] = end
        tmp = (None, chunkdic)
        arg_list.append(tmp)
    poolsize = 32
    print '开始下载jdb'
    starttime = time.time()
    pool = threadpool.ThreadPool(poolsize)
    reqst = threadpool.makeRequests(t_download, arg_list)
    [pool.putRequest(req) for req in reqst]
    pool.wait()
    print '%d seconds' % (time.time() - starttime)


if __name__ == "__main__":
    # 获取目标文件下载信息JdbFile
    target = get_target()
    # 若本地Jdb文件不存在，则新建
    if not os.path.exists(target.name):
        with open(target.name, "w") as f:
            pass
    # 开始下载
    # 1 使用多线程，分段下载
    # 1.1 根据JdbFile.size分段
    # 1.2 download方法，开启多线程，根据分段下载
    # 2 根据JdbFile.md5校验下载的病毒库完整性
    # 3 周期下载，每天12点
    download(target)