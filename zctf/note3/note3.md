# 漏洞点
漏洞点同note2差不多，就是少了一个show函数，没办法泄露数据

# 利用
这里同样采用unlink，不过由于没有show函数，需要自己构造泄露，因此把free的got表改为puts_plt+6，这样会重新计算出puts函数的地址，写入free_got中，然后调用delete函数就可以实现泄露了。
