# Cpp-dll-debugging-in-IDA
 Well, hare i was making reverse engineering in me application, where me was lost the font code T-T. But in the determinate moment, i found the call for my old .dll, where there calculate the token to granted access my server.
 But i laziness to rewrite my .dll, yes i do it :/, anyway i needed the use this .dll, but as? Good, let's start do this "tutorial".

 Firstly, i will use IDA (HexRays) and MSVC for this.

 For use the .dll we will firstly found this "real" calling, let's to this,
 .dll data:
 ```
name: CalculateToken.dll
typedef: ???
architeture: ???
```
Well, we're lost, but not afraid i'll use the magic of reverse engineering to discovery this, let's see:
an open my .dll i found this fucntion
```c++
int __cdecl sub_411920(int a1, char a2, int a3)
```
Wow, in the basic analisys we can assume that is ```x32``` because use ```int``` not ```__int64``` and i "granted" this typedef, then:
.dll data:
```
name: CalculateToken.dll
typedef: int (__cdecl)(int, char, int)
architeture: probabily x32
```
data obtained, now i'll analyse this function to the see each data type and verify is compatible.
see the function below:
```c++
int __cdecl sub_411920(int a1, char a2, int a3)
{
  int result; // eax
  unsigned int i; // [esp+D0h] [ebp-8h]

  result = __CheckForDebuggerJustMyCode(&unk_41C0F2);
  for ( i = 0; i < 20; ++i )
  {
    *(_BYTE *)(i + a3) = a2 ^ *(_BYTE *)(i + a1);
    result = i + 1;
  }
  return result;
}
```
This function is be wrong for me, firtly i'm fix the "int" but is array of byte, not int...
```c++
int __cdecl sub_411920(unsigned __int8 *a1, char a2, unsigned __int8 *a3)
{
  int result; // eax
  unsigned int i; // [esp+D0h] [ebp-8h]

  result = __CheckForDebuggerJustMyCode(&unk_41C0F2);
  for ( i = 0; i < 4; ++i )
  {
    a3[i] = a2 ^ a1[i];
    result = i + 1;
  }
  return result;
}
```
cool, this code wen been rewrite now, but i'm so lazy to use ctrl+c and ctrl+v and not rewrite, only consume that.
recap, .dll data:
```
name: CalculateToken.dll
typedef: int (__cdecl)(unsigned __int8*, char, unsigned __int8*)
architeture: probabily x32
```
but i'm find the input data, in the navigate in the IDA, i find this, is same twenty length:
```
69 20 6E 65 65 64 20 74 68 65 20 70 61 73 73 77 6F 72 64 21
```
and is passed in this function
```c++
sub_4113D9((int)v5, 5, (int)v4);
```
this number five probabily is the "a2"
go make call to the .dll in the msvc
```c++
auto main() -> void
{
	HMODULE hMod = LoadLibraryA("C:\\dll\\CalculateToken.dll");

	if (!hMod)
	{
		return;
	}

	typedef int(__cdecl* doCalculateToken)(unsigned __int8*, char, unsigned __int8*);

	doCalculateToken calculate = reinterpret_cast<doCalculateToken>(GetProcAddress(hMod, "doCalculateToken"));

	if (!calculate)
	{
		return;
	}


	unsigned char input[20] = 
	{
		0x69, 0x20, 0x6E, 0x65, 
		0x65, 0x64, 0x20, 0x74, 
		0x68, 0x65, 0x20, 0x70,
		0x61, 0x73, 0x73, 0x77, 
		0x6F, 0x72, 0x64, 0x21
	};

	char a2 = 5;
	
	unsigned char* out = reinterpret_cast<unsigned char*>(malloc(20 * sizeof(unsigned char)));

	int ret = calculate(input, a2, out);
}
```

after do this, you should be able to debug the .dll in ida
in the ida, follow the following steps:

1. go to debbuger > Select debbuger > Local Windows Debbuger
2. go to debbuger > Process options
3. fill the follow fields:
```
Application: our .exe c++
input file: out .dll
directory: our dir
```
and i'll be to debbuing the application inside the ida.

```
out: 6C 25 6B 60 60 61 25 71 6D 60 25 75 64 76 76 72 6A 77 61 24 
```
