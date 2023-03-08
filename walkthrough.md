

**Part4: we'll need to reverse engineer a binary [bomb] to get a sequence of passwords

```
nmap 10.12.100.0/24

Nmap scan report for 10.12.100.12
Host is up (0.0060s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
143/tcp open  imap
443/tcp open  https
993/tcp open  imaps


ssh laurie@10.12.100.12
330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4
```

`for IP in 10.12.100.{12..20} ; do ssh -o ConnectTimeout=1 laurie@$IP ; done`

too slow

use three ranges, each in a separate terminal
```
for IP in 10.12.100.{1..50} ; do ssh -o ConnectTimeout=1 -o NumberOfPasswordPrompts=1 laurie@$IP ; done
for IP in 10.12.100.{50..100} ; do ssh -o ConnectTimeout=1 -o NumberOfPasswordPrompts=1 laurie@$IP ; done
for IP in 10.12.100.{100..200} ; do ssh -o ConnectTimeout=1 -o NumberOfPasswordPrompts=1 laurie@$IP ; done
```
[UPDATE]

a faster and much easier soloution is to check the ARP cache table

```
arp -a

? (10.12.100.135) at (incomplete) on en0 ifscope [ethernet]
```

```
When a virtual machine (VM) is running on a host system,
it is assigned a virtual MAC address that is different from the host's physical MAC address. 
This virtual MAC address is used by the VM to communicate with other devices on the network.

When the VM sends packets to other devices, the host system's network interface card (NIC) forwards those packets on behalf of the VM. 
In order to do this, the host needs to know the MAC address of the destination device.
The host obtains this information by sending an ARP request to the network, 
asking for the MAC address of the device with the corresponding IP address.

When the host receives the ARP response with the MAC address, 
it stores this information in its ARP cache. Therefore, when you run the "arp -a" command on the host system,
you will see the MAC addresses of both physical and virtual devices that have communicated with the host system recently.
```

```
laurie@BornToSecHackMe:~$ ls
bomb  README
laurie@BornToSecHackMe:~$ cat README
Diffuse this bomb!
When you have all the password use it as "thor" user with ssh.

HINT:
P
 2
 b

o
4

laurie@BornToSecHackMe:~$ file bomb
bomb: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV)
```


```
(gdb) info func

0x08048b20  phase_1
0x08048b48  phase_2
0x08048b98  phase_3
0x08048ca0  func4
0x08048ce0  phase_4
0x08048d2c  phase_5
0x08048d98  phase_6
0x08048e94  fun7
0x08048ee8  secret_phase
0x08048f50  sig_handler
0x08048fb4  invalid_phase
0x08048fd8  read_six_numbers
0x08049018  string_length
0x08049030  strings_not_equal
0x0804908c  open_clientfd
0x08049160  initialize_bomb
0x0804917c  blank_line
0x080491b0  skip
0x080491fc  read_line
0x080492c0  send_msg
0x080494fc  explode_bomb
0x0804952c  phase_defused
```

```
main()
{
  initialize_bomb();
  printf("Welcome this is my little bomb !!!! You have 6 stages with\n");
  printf("only one life good luck !! Have a nice day!\n");
  uVar1 = read_line();
  phase_1(uVar1);
  phase_defused();
  printf("Phase 1 defused. How about the next one?\n");
  uVar1 = read_line();
  phase_2(uVar1);
  phase_defused();
  printf("That\'s number 2.  Keep going!\n");
  uVar1 = read_line();
  phase_3(uVar1);
  phase_defused();
  printf("Halfway there!\n");
  uVar1 = read_line();
  phase_4(uVar1);
  phase_defused();
  printf("So you got that one.  Try this one.\n");
  uVar1 = read_line();
  phase_5(uVar1);
  phase_defused();
  printf("Good work!  On to the next...\n");
  uVar1 = read_line();
  phase_6(uVar1);
  phase_defused();
  return 0;
}
```
```
(gdb) disass phase_1
Dump of assembler code for function phase_1:
   0x08048b20 <+0>:	push   %ebp
   0x08048b21 <+1>:	mov    %esp,%ebp
   0x08048b23 <+3>:	sub    $0x8,%esp
   0x08048b26 <+6>:	mov    0x8(%ebp),%eax
   0x08048b29 <+9>:	add    $0xfffffff8,%esp
   0x08048b2c <+12>:	push   $0x80497c0


 x/s 0x80497c0
0x80497c0:	 "Public speaking is very easy."

laurie@BornToSecHackMe:~$ echo "Public speaking is very easy." > phase_1
laurie@BornToSecHackMe:~$ ./bomb phase_1
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
Phase 1 defused. How about the next one?
```

```
(gdb) disass phase_2

   0x08048b50 <+8>:	mov    0x8(%ebp),%edx
   0x08048b56 <+14>:	lea    -0x18(%ebp),%eax
   0x08048b59 <+17>:	push   %eax
   0x08048b5a <+18>:	push   %edx
   0x08048b5b <+19>:	call   0x8048fd8 <read_six_numbers>
   0x08048b60 <+24>:	add    $0x10,%esp
   0x08048b63 <+27>:	cmpl   $0x1,-0x18(%ebp)

 prepare the parameters to call the function read_six_numbers, 
 which reads six integers from standard input and stores them in an array. 
 The first parameter is the address of the local variable just loaded into the eax register, 
 and the second parameter is the value in the edx register, which is the first parameter passed to the function.

The instruction cmpl $0x1,-0x18(%ebp) is comparing the value at memory address %ebp-0x18 with 0x1.
This value is one of the parameters passed to the function read_six_numbers.

Therefore, this instruction is actually comparing the 1st parameter passed to read_six_numbers with the value 0x1.
```

```
Since the first element of tab_six is stored in %edx,
any reference to tab_six[0] in the subsequent code would be equivalent to (%edx).
However, we can see in the code that the first element is actually accessed using the expression tab_six+1,
which would be equivalent to (%edx + 4) since the size of an integer is 4 bytes.
This implies that the first element of tab_six is actually located at %edx + 4.

Therefore, any reference to tab_six[i] in the subsequent code would be equivalent to (%edx + 4 + i*4).
Since i starts at 1, the indexing of the array starts at 1 in this assembly code.

The reason is that the first element of the array is accessed using %edx,
which is a register that stores a memory address.
The instruction movl (%edx),%eax is used to move the contents of the first element 
of the array into the %eax register. 
This implies that the first element of the array is located at %edx.

Then, the instruction lea 0x4(%edx),%eax is used to calculate 
the address of the 2nd element of the array, which is %edx + 4.
This means that the 2nd element of the array is located 4 bytes away from the first element.

Therefore, the indexing of the array starts at 1
```

```
while syntax:

  i = 1;
  do 
  {
    if (array[i + 1] != (i + 1) * array[i])
      explode_bomb();
    
    i = i + 1;
  } while (i < 6);

for syntax:

 for (int i = 1; i <= 5; i++) 
 {
        if (tab_six[i+1] != (i+1) * tab_six[i])
            explode_bomb();
        
  }
``` 

RECAP:
```
laurie@BornToSecHackMe:~$ cat payload
Public speaking is very easy.
1 2
```
```
1+1 * t[1] ==> 2 * 1  = 2   = t[1+1] 
2+1 * t[2] ==> 3 * 2  = 6   = t[2+1]
3+1 * t[3] ==> 4 * 6  = 24  = t[3+1]
4+1 * t[4] ==> 5 * 24 = 120 = t[4+1]
5+1 * t[5] ==> 6 * 120= 720 = t[5+1]
```


```
laurie@BornToSecHackMe:~$ echo "1 2 6 24 120 720" >> payload
laurie@BornToSecHackMe:~$ ./bomb payload
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
Phase 1 defused. How about the next one?
That's number 2.  Keep going!
```

```
void phase_3(char *param_1)

{
  int iVar1;
  char cVar2;
  uint nbr1;
  char character;
  int nbr2;
  
  iVar1 = sscanf(param_1,"%d %c %d",&nbr1,&character,&nbr2);
  if (iVar1 < 3) 
  {
    explode_bomb();
  }
  switch(nbr1) 
  {
    case 0:
      cVar2 = 'q';
      if (nbr2 != 777) 
      {
        explode_bomb();
      }
      break;
    case 1:
      cVar2 = 'b';
      if (nbr2 != 214) 
      {
        explode_bomb();
      }
      break;
    case 2:
      cVar2 = 'b';
      if (nbr2 != 755) 
      {
        explode_bomb();
      }
      break;
    case 3:
      cVar2 = 'k';
      if (nbr2 != 251) 
      {
        explode_bomb();
      }
      break;
    case 4:
      cVar2 = 'o';
      if (nbr2 != 160) {
        explode_bomb();
      }
      break;
    case 5:
      cVar2 = 't';
      if (nbr2 != 458) 
      {
        explode_bomb();
      }
      break;
    case 6:
      cVar2 = 'v';
      if (nbr2 != 780) 
      {
        explode_bomb();
      }
      break;
    case 7:
      cVar2 = 'b';
      if (nbr2 != 524) 
      {
        explode_bomb();
      }
      break;
    default:
      cVar2 = 'x';
      explode_bomb();
  }
  if (cVar2 != character) 
  {
    explode_bomb();
  }
  return;
}
```

```
laurie@BornToSecHackMe:~$ cat payload
Public speaking is very easy.
1 2 6 24 120 720
7 b 524

laurie@BornToSecHackMe:~$ ./bomb payload
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
Phase 1 defused. How about the next one?
That's number 2.  Keep going!
Halfway there!

```

```
void phase_4(char *param_1)
{
  int ret;
  int inputNbr;
  
  ret = sscanf(param_1,"%d",&inputNbr);
  if ((ret != 1) || (inputNbr < 1))
    explode_bomb();
  
  ret = func4(inputNbr);
  if (ret != 55)
    explode_bomb();
  
  return;
}


int func4(int input)
{
  int i;
  int ret;
  
  if (input < 2)
    ret = 1;
  
  else 
  {
    i = func4(input - 1);
    ret = func4(input - 2);
    ret = ret + i;
  }
 
  return ret;
}
```

```
#include<stdio.h>

int func4(int input)
{
  int i;
  int ret;
  
  if (input < 2)
    ret = 1;
  
  else 
  {
    i = func4(input - 1);
    ret = func4(input - 2);
    ret = ret + i;
  }
 
  return ret;
}

int main()
{
    for (int i = 1; i<=100; i++)
    {
        printf("res{%d} =  %d\n", i, func4(i));
        if(func4(i) == 55)
            break;
    }
    return (0);
}

    
    res{1} =  1
    res{2} =  2
    res{3} =  3
    res{4} =  5
    res{5} =  8
    res{6} =  13
    res{7} =  21
    res{8} =  34
    res{9} =  55
```

```
laurie@BornToSecHackMe:~$ echo "9" >> payload

laurie@BornToSecHackMe:~$ ./bomb payload
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
Phase 1 defused. How about the next one?
That's number 2.  Keep going!
Halfway there!
So you got that one.  Try this one.
```

















































