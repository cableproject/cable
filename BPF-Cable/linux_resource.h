#include<stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql/mysql.h>

MYSQL my_connection;


typedef struct CPU_PACKED         //定义一个cpu occupy的结构体
{
char name[20];             //定义一个char类型的数组名name有20个元素
unsigned int user;        //定义一个无符号的int类型的user
unsigned int nice;        //定义一个无符号的int类型的nice
unsigned int system;    //定义一个无符号的int类型的system
unsigned int idle;         //定义一个无符号的int类型的idle
unsigned int iowait;
unsigned int irq;
unsigned int softirq;
}CPU_OCCUPY;

typedef struct MEM_PACKED         //定义一个mem occupy的结构体
{
        char name[20];      //定义一个char类型的数组名name有20个元素
        unsigned long total;
        char name2[20];
}MEM_OCCUPY;
 
 
typedef struct MEM_PACK         //定义一个mem occupy的结构体
{
        double total,used_rate;
}MEM_PACK;

typedef struct DEV_MEM         //定义一个mem occupy的结构体
{
        double total,used_rate;
}DEV_MEM;

double getCpuRate(void);
MEM_PACK *get_memoccupy (void);
DEV_MEM *get_devmem(void);
MYSQL *initResourceMysql(void);
int insertResourceMysql(MYSQL* connect,long timestape, int type,double value,long long TEID, long long ip,int is_up);
void closeMysql(MYSQL* connect);