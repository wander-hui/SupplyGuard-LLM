package com.example.demo;

import com.alibaba.fastjson.JSON;
import javax.servlet.http.HttpServletRequest;
import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;

public class VulnController {

    // CWE-502: Fastjson 反序列化外部输入
    public Object handle(HttpServletRequest request) throws Exception {
        String body = request.getParameter("data");
        Object obj = JSON.parseObject(body);       // sink: fastjson parseObject
        return obj;
    }

    // CWE-78: Runtime.exec 执行外部输入
    public void runCmd(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        Runtime.getRuntime().exec("ping " + host);  // sink: Runtime.exec
    }

    // CWE-502: 原生反序列化
    public Object nativeDeser(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();                    // sink: readObject
    }
}
