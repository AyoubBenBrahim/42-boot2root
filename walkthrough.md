

ull find the full project [here](https://github.com/AyoubBenBrahim/42-Boot2Root-teamWork) 

# Part4: we'll need to reverse engineer a binary [bomb] to get a sequence of passwords

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

UPDTAE

fping is way faster = Ping a range of IP addresses in parallel

```
docker run -it --rm networkstatic/fping -s -g 10.12.100.1 10.12.100.254 -r 1 | grep alive


10.12.100.33 is alive
10.12.100.43 is alive
10.12.100.120 is alive
10.12.100.129 is alive
10.12.100.135 is alive
10.12.100.247 is alive
```
`docker run -it --rm networkstatic/fping -s -g 10.12.100.0/24 -r 1 | grep alive`

`docker run -it --rm networkstatic/fping -s -g 10.12.100.0/24 -r 1 | grep alive | awk '{print $1}'`
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

```c
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
## Phase_1
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

## Phase_2

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


while syntax:
```c
  i = 1;
  do 
  {
    if (array[i + 1] != (i + 1) * array[i])
      explode_bomb();
    
    i = i + 1;
  } while (i < 6);
```
for syntax:
```c
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
obviously This is a factorial series

```
laurie@BornToSecHackMe:~$ echo "1 2 6 24 120 720" >> payload
laurie@BornToSecHackMe:~$ ./bomb payload
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
Phase 1 defused. How about the next one?
That's number 2.  Keep going!
```

## Phase_3

```c
void phase_3 (char *param_1)
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

## Phase_4

```c
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

```c
#include<stdio.h>

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
Fibonacci sequense
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

## Phase_5

```
   0x08048d4f <+35>:	lea    -0x8(%ebp),%ecx
   0x08048d52 <+38>:	mov    $0x804b220,%esi
   0x08048d57 <+43>:	mov    (%edx,%ebx,1),%al
   0x08048d5a <+46>:	and    $0xf,%al
   0x08048d5c <+48>:	movsbl %al,%eax
   0x08048d5f <+51>:	mov    (%eax,%esi,1),%al
   0x08048d62 <+54>:	mov    %al,(%edx,%ecx,1)
   0x08048d65 <+57>:	inc    %edx
   0x08048d66 <+58>:	cmp    $0x5,%edx
```
```
The given assembly code is a block of code that takes a 6-byte input and encodes it using a substitution cipher.

At the beginning of the code, the address 0x804b220 is loaded into the register %esi,
which contains the string "isrveawhobpnutfg". This string serves as a lookup table for the substitution cipher.

The input string is located at %ebp-0x8, and its characters are accessed sequentially using a loop that runs 6 times.
The variable %edx holds the current loop index, starting at 0,
and %ebx is used to calculate the memory address of the current character in the input string.

The current character is loaded into %al, and the lower 4 bits are extracted using the and instruction with a bitmask of 0xf.
This value is then used as an index into the substitution table %esi to get the encoded character.
The encoded character is loaded into %al, 
and then stored in the output string located at %ebp-0x8 with an offset of %edx bytes from the beginning of the string.

After each character is encoded and stored, %edx is incremented, and the loop continues until %edx reaches 6.
At this point, the encoding is complete, and control is returned to the calling function.
```

```c
#include<stdio.h>
#include<string.h>
#include<stdlib.h>

void phase_5(char *input)
{
	char *indexer = "isrveawhobpnutfg";
	char curr_char;

	if (strlen(input) != 6)
 	{
     		printf("explode_bomb();");
     		exit(0);
 	}

    	for (int i = 0; i < 6; i++)
    	{
		curr_char = *(input + i) & 0xf;

		printf("input[i] = %d|%c\ninput[i] & 0xf = %d\nindexer[curr_char] = 	[%c]\n", input[i],input[i], curr_char, indexer[curr_char]);

		input[i] = indexer[curr_char];

		printf("--------------\n");
	}

	if (strcmp(input, "giants") != 0)
    	{
    		printf("explode_bomb();");
   		exit(0);
	}
	else
 		printf("OK");
}

int main(int ac, char **av)
{
	phase_5(av[1]);
}

```

```c
=== Output

0   1   2   3   4   5   6   7   8   9   10   11   12   13   14   15                     
i | s | r | v | e | a | w | h | o | b | p  | n  | u  | t  | f  | g


./a.out opukma

input[i] = 111|o                    111 = 1101111 & 1111 = 0001111 = 15      000 001 011 111 | 100 110 | 101  (0 to 7) & f   
input[i] & 0xf = 15
indexer[curr_char] = 	[g]
--------------
input[i] = 112|p                    112 = 1110000 & 1111 = 0000000 = 0 
input[i] & 0xf = 0
indexer[curr_char] = 	[i]
-------------- 									          							
input[i] = 117|u                    117 = 1110101 & 1111 = 0000101 = 5             111 => 7 << 4 => 1110000 | 5 => 1110101 = 117 (97|a -> 122|z)
input[i] & 0xf = 5
indexer[curr_char] = 	[a]
--------------
input[i] = 107|k                    107 = 1101011 & 1111 = 0001011 = 11            110 = 6 << 4 = 1100000 | 11 = 1101011   
input[i] & 0xf = 11
indexer[curr_char] = 	[n]
--------------
input[i] = 109|m
input[i] & 0xf = 13
indexer[curr_char] = 	[t]
--------------
input[i] = 97|a
input[i] & 0xf = 1
indexer[curr_char] = 	[s]
--------------

OK%
```

reverse substitution cipher

```c
#include<stdio.h>
#include<string.h>
#include<stdlib.h>

int find_index(char c)
{
	int i;
	char cipher[] = "isrveawhobpnutfg";

	for (i = 0; i < strlen(cipher); i++) 
	{
        	if (cipher[i] == c)
            	    return i;
        
    	}
    	return -1;
}

void reverse_phase_5()
{
	char decipher[] = "giants";
  
 	for (int i = 0; i < 6; i++)
    	{
		int index = find_index(decipher[i]);
		printf ("index =  %d \n", index);

		for (int j = 0; j <= 7; j++)
		{
			int shift = j << 4;
			int bitwise_or = shift | index;
			if (bitwise_or >= 'a' && bitwise_or <= 'z')
			{
				printf ("%c \n", bitwise_or);
				break;
			}
		}
		printf ("-----\n");
    }
}

int main()
{
    	reverse_phase_5();
}
```

```
➜  Desktop gcc reverse_phase_5.c -o reverse_phase_5
➜  Desktop ./reverse_phase_5
opekma%
```
```
laurie@BornToSecHackMe:~$ cat payload
Public speaking is very easy.
1 2 6 24 120 720
7 b 524
9
opekma
```

## Phase_6
```
0x08048dae <+22>:	lea    -0x18(%ebp),%eax
0x08048db3 <+27>:	call   0x8048fd8 <read_six_numbers>

0x08048db3 <+27>: The function calls the read_six_numbers function, 
which reads in six integers from standard input and stores them in the array located at [ebp-0x18].
```

```
0x08048dc0 <+40>:	lea    -0x18(%ebp),%eax
0x08048dc3 <+43>:	mov    (%eax,%edi,4),%eax
0x08048dc6 <+46>:	dec    %eax
0x08048dc7 <+47>:	cmp    $0x5,%eax
0x08048dca <+50>:	jbe    0x8048dd1 <phase_6+57>
0x08048dcc <+52>:	call   0x80494fc <explode_bomb>


compares the value in eax to 5.
0x08048dca <+50>: If the value in eax is less than or equal to 5, 
the function jumps to 0x8048dd1 to continue execution. Otherwise, it calls the explode_bomb function and terminates.
```

```

  0x08048dd9 <+65>:	lea    0x0(,%edi,4),%eax
  0x08048de0 <+72>:	mov    %eax,-0x38(%ebp)
  0x08048de3 <+75>:	lea    -0x18(%ebp),%esi
  0x08048de6 <+78>:	mov    -0x38(%ebp),%edx
  0x08048de9 <+81>:	mov    (%edx,%esi,1),%eax
  0x08048dec <+84>:	cmp    (%esi,%ebx,4),%eax
  0x08048def <+87>:	jne    0x8048df6 <phase_6+94>
  0x08048df1 <+89>:	call   0x80494fc <explode_bomb>
   
<+65>:	lea    eax,[edi*4+0x0]  ==> eax = edi * 4 + 0

This instruction is used to calculate an index into an array, where each element of the array is 4 bytes in size.
By multiplying the index (in "edi") by 4, we obtain the offset (in bytes) from the start of the array to the desired element.
Storing this offset in "eax" allows us to use it to access the desired element later in the program.

The array stores integers, which are typically 4 bytes (32 bits) in size. Therefore,
each element of the array takes up 4 bytes of memory. To access the i-th element of the array, 
the program needs to calculate the memory address of the i-th element. Since each element takes up 4 bytes, 
the address of the i-th element is the base address of the array plus i times 4 (i.e., the number of elements before it,
multiplied by the size of each element).

0x08048dec <+84>:   cmp    eax,DWORD PTR [esi+ebx*4]
0x08048def <+87>:   jne    0x8048df6 <phase_6+94>

Here, the instruction cmp compares the value in eax (which was loaded from the (edi+0)-th index of the input array)
with the value at the address [esi+ebx*4] (which corresponds to the (edi+1)-th index of the input array).
If these values are not equal, jumps to the explode_bomb function.


```

```
(gdb) b main
Breakpoint 1 at 0x80489b7: file bomb.c, line 36.
(gdb) run


(gdb) define loop_nodes
>set $i = 0
>set $next = $arg0
>while ($i < 6)
 >x/3wx $next
 >set $next = *(unsigned int*)($next+8)
 >set $i= $i+1
 >end
>end

(gdb) loop_nodes 0x804b26c

0x804b26c <node1>:	0x000000fd	0x00000001	0x0804b260
0x804b260 <node2>:	0x000002d5	0x00000002	0x0804b254
0x804b254 <node3>:	0x0000012d	0x00000003	0x0804b248
0x804b248 <node4>:	0x000003e5	0x00000004	0x0804b23c
0x804b23c <node5>:	0x000000d4	0x00000005	0x0804b230
0x804b230 <node6>:	0x000001b0	0x00000006	0x00000000

```
better formating
```
(gdb) define loop_nodes
>set $i = 0
>set $next = $arg0
>while($i < 6)
 >printf "%#x  %3d  %3d  %#x\n" , $next , *$next, *($next+4), *($next+8)
 >set $next = *(unsigned int *)($next+8)
 >set $i = $i + 1
 >end
>end
(gdb) loop_nodes 0x804b26c
0x804b26c  253    1  0x804b260
0x804b260  725    2  0x804b254
0x804b254  301    3  0x804b248
0x804b248  997    4  0x804b23c
0x804b23c  212    5  0x804b230
0x804b230  432    6  0
```

the order in which the values would be in decreasing order:
```
997 | 725 | 432 | 301 | 253 | 212
 4  |  2  |  6  |  3  |  1  |  5
```

i worked on a better formated macro

```
notice the pattern

(gdb) p/x 0x804b26c-(12*0)
$46 = 0x804b26c
(gdb) p/x &node1
$47 = 0x804b26c

(gdb) p/x 0x804b26c-(12*4)
$43 = 0x804b23c
(gdb) p/x &node5
$42 = 0x804b23c

(gdb) p/x 0x804b26c-(12*5)
$44 = 0x804b230
(gdb) p/x &node6
$45 = 0x804b230
```
gdb macro
```
define sorted_nodes
  set $nodes = (int (*)[2])$arg0
  set $i = 0
  while ($i < 6)
    set $nodes[$i+1][0] = *(int *)($arg0 - (($i + 1) * 12))
    set $nodes[$i+1][1] = *(int *)($arg0 - (($i + 1) * 12) + 4)
    set $i = $i + 1
  end

  #BUBLE SORT

set $i = 0
  while ($i < 6)
    set $j = 0
    while ($j < 6 - $i - 1)
      if ($nodes[$j+1][0] > $nodes[$j][0])
        set $temp = $nodes[$j][0]
        set $nodes[$j][0] = $nodes[$j+1][0]
        set $nodes[$j+1][0] = $temp
        
        set $temp = $nodes[$j][1]
        set $nodes[$j][1] = $nodes[$j+1][1]
        set $nodes[$j+1][1] = $temp
      end
      set $j = $j + 1
    end
    set $i = $i + 1
  end

#print 2d array

set $i = 0
  while ($i < 6)
    printf "%3d ", $nodes[$i][0]
    set $i = $i + 1
  end
  printf "\n"
  set $i = 0
  while ($i < 6)
    printf "%3d ", $nodes[$i][1]
    set $i = $i + 1
  end
  printf "\n"
end
```
output
```
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/laurie/bomb

(gdb) sorted_nodes 0x804b26c

997 725 432 301 253 212
  4   2   6   3   1   5
```
```
laurie@BornToSecHackMe:~$ cat payload
Public speaking is very easy.
1 2 6 24 120 720
7 b 524
9
opekma
4 2 6 3 1 5
laurie@BornToSecHackMe:~$ ./bomb payload
Welcome this is my little bomb !!!! You have 6 stages with
only one life good luck !! Have a nice day!
Phase 1 defused. How about the next one?
That's number 2.  Keep going!
Halfway there!
So you got that one.  Try this one.
Good work!  On to the next...
Congratulations! You've defused the bomb!
```

combining the results of the phases

```
thor:Publicspeakingisveryeasy.126241207201b2149opekmq426135
```

ps: try all the combinations of opekm...
and check the subject for the reordring of th pwd





















