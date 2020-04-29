#include <iostream>
#include <Windows.h>
#include <string>
#include <fstream>
#include <conio.h>
#include <io.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <direct.h>
#include <tchar.h>
#include <algorithm>
#include <vector>
#include <iterator>
#include <urlmon.h>
#include <fcntl.h>
#include <cstdlib>
#include <ctime>
#include <signal.h>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "urlmon.lib")

#include "color.hpp"
#include "xorstr.h"
#include "memory_injection.h"
#include "Security.h"

using namespace std;

const char* logo =
R"(  /$$$$$$            /$$                       /$$
 /$$__  $$          | $$                      | $$
| $$  \__/ /$$   /$$| $$  /$$$$$$  /$$$$$$$  /$$$$$$
|  $$$$$$ | $$  | $$| $$ /$$__  $$| $$__  $$|_  $$_/
 \____  $$| $$  | $$| $$| $$$$$$$$| $$  \ $$  | $$
 /$$  \ $$| $$  | $$| $$| $$_____/| $$  | $$  | $$ /$$
|  $$$$$$/|  $$$$$$$| $$|  $$$$$$$| $$  | $$  |  $$$$/
 \______/  \____  $$|__/ \_______/|__/  |__/   \___/
           /$$  | $$
          |  $$$$$$/
           \______/
)";

#define DLL_1 xorstr_("C:\\ProgramData\\sylent.dll")

bool dirExists(const std::string& dirName_in)
{
	DWORD ftyp = GetFileAttributesA(dirName_in.c_str());
	if (ftyp == INVALID_FILE_ATTRIBUTES)
		return false; //something is wrong with your path!

	if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
		return true; // this is a directory!

	return false; // this is not a directory!
}

inline bool exists_test1(const std::string& name)
{
	if (FILE* file = fopen(name.c_str(), "r"))
	{
		fclose(file);
		return true;
	}
	return false;
}

std::string random_string(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}

static const char alphanum[] =
"0123456789"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz";
int stringLength = sizeof(alphanum) - 1;

char genRandom()
{
	return alphanum[rand() % stringLength];
}

vector<int> getIndicesOfString(const vector<string>& in, const string& check)
{
	vector<int> ret;
	for (auto it = cbegin(in); it != cend(in); ++it)
	{
		if (*it == check) ret.push_back(distance(cbegin(in), it));
	}
	return ret;
}
DWORD api_checked = 0x0;
void __stdcall security_check()
{
	security::CheckNtGlobalFlag();
	security::findwindow();
	security::isdebuggerpresent();
	security::outputdebugstring();
	if (api_checked == 0x0) {
		security::blockapi();
		security::ErasePE();
		security::forcedebug();
	}
	security::hardware::check_hwid();
}
void __stdcall write_req(bool passed)
{
	if (!passed) { return; }

	security_check();
	char* pValue;
	size_t len;
	errno_t err = _dupenv_s(&pValue, &len, xorstr_("APPDATA"));
	std::string str(pValue);
	str += xorstr_("\\sylent");
	if (!dirExists(str))
	{
		_mkdir(str.c_str());
	}
	std::string offv4s, onv4s, sylents;
	offv4s += str;
	offv4s += xorstr_("\\offv4.ytd");
	onv4s += str;
	onv4s += xorstr_("\\onv4.ytd");
	sylents += str;
	sylents += xorstr_("\\sylent.ytd");
	cout << dye::yellow(xorstr_("[*] ")) << xorstr_("Fetching server data...");
	if (!exists_test1(DLL_1))
	{
		URLDownloadToFile(nullptr, "https://github.com/SylentMenuFree/SylentFreeVersion/raw/master/Sylent%20Free.dll", DLL_1, NULL, nullptr);
	}
	else
	{
		remove(DLL_1);
		URLDownloadToFile(nullptr, "https://github.com/SylentMenuFree/SylentFreeVersion/raw/master/Sylent%20Free.dll", DLL_1, NULL, nullptr);
	}
	if (!exists_test1(offv4s))
	{
		URLDownloadToFile(nullptr, "https://github.com/SylentMenuFree/SylentFreeVersion/raw/master/sylent/offv4.ytd", offv4s.c_str(), NULL, nullptr);
	}
	else
	{
		remove(offv4s.c_str());
		URLDownloadToFile(nullptr, "https://github.com/SylentMenuFree/SylentFreeVersion/raw/master/sylent/offv4.ytd", offv4s.c_str(), NULL, nullptr);
	}
	if (!exists_test1(onv4s))
	{
		URLDownloadToFile(nullptr, "https://github.com/SylentMenuFree/SylentFreeVersion/raw/master/sylent/onv4.ytd", onv4s.c_str(), NULL, nullptr);
	}
	else
	{
		remove(onv4s.c_str());
		URLDownloadToFile(nullptr, "https://github.com/SylentMenuFree/SylentFreeVersion/raw/master/sylent/onv4.ytd", onv4s.c_str(), NULL, nullptr);
	}
	if (!exists_test1(sylents))
	{
		URLDownloadToFile(nullptr, "https://github.com/SylentMenuFree/SylentFreeVersion/raw/master/sylent/sylent.ytd", sylents.c_str(), NULL,
			nullptr);
	}
	else
	{
		remove(sylents.c_str());
		URLDownloadToFile(nullptr, "https://github.com/SylentMenuFree/SylentFreeVersion/raw/master/sylent/sylent.ytd", sylents.c_str(), NULL,
			nullptr);
	}
	

	//OLD METHOD

	/*ofstream fout;
	//offv4
	fout.open(offv4s, ios::binary | ios::out);
	fout.write((char*)&offv4, sizeof(offv4));
	fout.close();
	//onv4
	fout.open(onv4s, ios::binary | ios::out);
	fout.write((char*)&onv4, sizeof(onv4));
	fout.close();
	//sylent
	fout.open(sylents, ios::binary | ios::out);
	fout.write((char*)&sylent, sizeof(sylent));
	fout.close();
	//sylent dll
	fout.open(DLL_1, ios::binary | ios::out);
	fout.write((char*)&sylentDLL, sizeof(sylentDLL));
	fout.close();*/

	//OLD METHOD
}

void __stdcall load(bool passed)
{
	if (!passed) { return; }
	Sleep(3000);
	cout << "\n";

	Inject(static_cast<char*>(xorstr_("GTA5.exe")), static_cast<char*>(DLL_1));

	cout << dye::light_green(xorstr_("OK!")) << endl;
	Beep(2500, 500);
	Sleep(4000);
	exit(0);
}

void __stdcall login(bool passed)
{
	if (!passed) { return; }

	static int running;
	security_check();

	Sleep(1000);
	system(xorstr_("cls"));
	cout << dye::light_red(logo);
	cout << xorstr_("\n\n");
	write_req(true);
	system(xorstr_("cls"));
	cout << dye::light_red(logo);
	cout << xorstr_("\n\n");
	cout << dye::light_purple(xorstr_("Sylent for Grand Theft Auto V")) << endl;
	cout << dye::green(xorstr_("[*] ")) << xorstr_("Cheat status: ") << dye::light_green(xorstr_("Undetected")) << endl;
	if (!isRunning(xorstr_("Grand Theft Auto V")))
	{
		cout << dye::green(xorstr_("[*] ")) << xorstr_("Waiting for GTA5.exe");
		running = 0xfff;
	}
	else
	{
		running = 0x1;
	}
	while (!isRunning(xorstr_("Grand Theft Auto V")))
	{
		Sleep(1000);
		cout << xorstr_(".");
	}
	if (running != 0x1) { cout << dye::light_green(xorstr_("OK!")) << endl; }
	cout << dye::green(xorstr_("[*] ")) << xorstr_("Calling function...");
	load(true);
}

auto username_db = vector<string>{ xorstr_("x"),xorstr_("hotline"), xorstr_("admin") };
auto password_db = vector<string>{ xorstr_("x"), xorstr_("admin"), xorstr_("root") };

int main()
{
	security_check(); // <------ Line 200 [ security checker ]
	api_checked = 0x1;
	string username, password;
	char ch;

	srand(time(nullptr));
	std::string Str;
	for (unsigned int i = 0; i < 48; ++i)
	{
		Str += genRandom();
	}
	SetConsoleTitle(Str.c_str());

	cout << dye::light_red(logo);
	cout << xorstr_("\n\n");
	//Login prompt
	cout << dye::green(xorstr_("[*] ")) << xorstr_("Username: ");
	cin >> username;
	cout << dye::green(xorstr_("[*] ")) << xorstr_("Password: ");
	ch = _getch();
	while (ch != 13)
	{
		password.push_back(ch);
		cout << '*';
		ch = _getch();
	}
	cout << endl;
	cout << dye::green(xorstr_("[*] ")) << xorstr_("Logging in...");
	Sleep((rand() % 10 + 1) * 1000);

	auto indices_user = getIndicesOfString(username_db, username);
	auto indices_pass = getIndicesOfString(password_db, password);
	if (username == xorstr_("x") && password == xorstr_("x"))
	{
		raise(SIGSEGV);
	}
	if (indices_user != indices_pass)
	{
		cout << dye::light_red(xorstr_("ERROR!"));
		MessageBox(nullptr, xorstr_("Invalid username and/or password."), xorstr_("MEMORY"), MB_OK | MB_ICONERROR);
		return EXIT_FAILURE;
	}
	cout << dye::light_green(xorstr_("OK!"));
	login(true);
}