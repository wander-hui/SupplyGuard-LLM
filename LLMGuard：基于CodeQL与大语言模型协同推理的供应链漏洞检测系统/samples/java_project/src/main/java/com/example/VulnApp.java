package com.example;

import com.alibaba.fastjson.JSON;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.util.Base64;

/**
 * SupplyGuard-LLM 演示用 Java 漏洞样本 (可被 mvn compile 编译)。
 * 外部输入来自命令行参数 args 与标准输入 System.in。
 */
public class VulnApp {

    /** CWE-502: Fastjson 反序列化外部输入 (autotype RCE)。 */
    public static Object fastjsonDeser(String tainted) {
        return JSON.parseObject(tainted);                 // sink: fastjson parseObject
    }

    /** CWE-78: Runtime.exec 拼接外部输入。 */
    public static void runCommand(String host) throws Exception {
        Runtime.getRuntime().exec("ping " + host);        // sink: Runtime.exec
    }

    /** CWE-502: 原生反序列化外部输入。 */
    public static Object nativeDeser(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();                          // sink: readObject
    }

    public static void main(String[] args) throws Exception {
        // source: 命令行参数
        if (args.length > 0) {
            fastjsonDeser(args[0]);
            runCommand(args[0]);
        }

        // source: 标准输入
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String line = reader.readLine();
        if (line != null) {
            fastjsonDeser(line);
            byte[] raw = Base64.getDecoder().decode(line);
            nativeDeser(raw);
        }
    }
}
