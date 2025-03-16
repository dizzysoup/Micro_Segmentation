# 操作手冊

先執行ryu-project 專案，這樣SDN Controller 就會成功執行
```
 ryu-manager app.py
```
再使用mininet 連接 SDN Controller
```
  mn --topo single,3 --controller remote,ip=127.0.0.1,port=6633
```
接著啟動ryu-backend，此為DataCenter的後端
```
  python app.py
```

最後啟動前端介面 ryu-dashboard
```
  npm start
```


## POST 測試

### 測試SDN 的policy

* ICMP

    epg.json
    ```json
        {
            "IP": "192.168.173.101",
            "function": "Service",
            "Priority": "User",
            "Type": "Shipping",
            "Security": "Normal"
        },
        {
            "IP": "192.168.173.103",
            "function": "Database",
            "Priority": "User",
            "Type": "Shipping",
            "Security": "Normal"
        }
    ```
  
  ```
   POST http://sdn.yuntech.poc.com/datacenter/intent
   {
        "method" : "deny",
        "egress" : "Service",
        "egresstype" : "function",
        "port" : "",
        "protocol" : "ICMP",
        "ingress" : "Database",
        "ingresstype" : "function"
    }
  ```


### 測試 iptables 的 policy 
