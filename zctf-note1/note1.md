# 漏洞点
  明显的堆溢出
  在new函数中,content为256字节
  ```
  vnote_10 = malloc(0x170uLL);
  puts("Enter the title:");
  input(vnote_10 + 2, 64LL, 10LL);
  puts("Enter the type:");
  input(vnote_10 + 10, 32LL, 10LL);
  puts("Enter the content:");
  input(vnote_10 + 14, 256LL, 10LL);
  ```
  在edit函数中，
  ```
  
  ```
