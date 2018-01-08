# 漏洞点
 如下所示，漏洞点为，size由用户输入，可以为0，而在inputstring函数中，以a2-1作为循环条件，可为-1，这里通过汇编指令，发现此处是ja跳转指令，即无符号跳转指令，因此，这里在无符号的情况下-1是很大的数据，因此会造成溢出
```
  puts("Input the length of the note content:(less than 128)");
  size = inputint();
  if ( size > 0x80 )
    return puts("Too long");
  buf = (const char *)malloc(size);
  puts("Input the note content:");
  inputstring((__int64)buf, size, 10);
```

```
unsigned __int64 __fastcall inputstring(__int64 a1, __int64 a2, char a3)
{
  char buf; // [rsp+2Fh] [rbp-11h]@2
  unsigned __int64 i; // [rsp+30h] [rbp-10h]@1
  __int64 v7; // [rsp+38h] [rbp-8h]@2

  for ( i = 0LL; a2 - 1 > i; ++i )
  {
    v7 = read(0, &buf, 1uLL);
    if ( v7 <= 0 )
      exit(-1);
    if ( buf == a3 )
      break;
    *(_BYTE *)(i + a1) = buf;
  }
  *(_BYTE *)(a1 + i) = 0;
  return i;
}
```
# 利用
  这里不同于note1，这些堆块是保存在一个固定地址的数据中，因此这里采用的unlink技术<br>
  在使用unlink技术时，通过堆溢出，覆盖后一堆块的pre size和size字段，从而使得其寻址到自己fake的堆块
