#include "linux_resource.h"

double cal_cpuoccupy(CPU_OCCUPY *o, CPU_OCCUPY *n)
{
    double od, nd;
    double id, sd;
    double cpu_use;

    od = (double)(o->user + o->nice + o->system + o->idle + o->softirq + o->iowait + o->irq); //第一次(用户+优先级+系统+空闲)的时间再赋给od
    nd = (double)(n->user + n->nice + n->system + n->idle + n->softirq + n->iowait + n->irq); //第二次(用户+优先级+系统+空闲)的时间再赋给od

    id = (double)(n->idle); //用户第一次和第二次的时间之差再赋给id
    sd = (double)(o->idle); //系统第一次和第二次的时间之差再赋给sd
    if ((nd - od) != 0)
        cpu_use = 100.0 - ((id - sd)) / (nd - od) * 100.00; //((用户+系统)乖100)除(第一次和第二次的时间差)再赋给g_cpu_used
    else
        cpu_use = 0;
    return cpu_use;
}

void get_cpuoccupy(CPU_OCCUPY *cpust)
{
    FILE *fd;
    char buff[256];
    CPU_OCCUPY *cpu_occupy;
    cpu_occupy = cpust;
    char *result;
    fd = fopen("/proc/stat", "r");
    result = fgets(buff, sizeof(buff), fd);
    if (result == NULL)
    {
        printf("fgets error\n");
    }

    sscanf(buff, "%s %u %u %u %u %u %u %u", cpu_occupy->name, &cpu_occupy->user, &cpu_occupy->nice, &cpu_occupy->system, &cpu_occupy->idle, &cpu_occupy->iowait, &cpu_occupy->irq, &cpu_occupy->softirq);

    fclose(fd);
}

double getCpuRate(void)
{
    CPU_OCCUPY cpu_stat1;
    CPU_OCCUPY cpu_stat2;
    double cpu;
    get_cpuoccupy((CPU_OCCUPY *)&cpu_stat1);
    sleep(1);

    //第二次获取cpu使用情况
    get_cpuoccupy((CPU_OCCUPY *)&cpu_stat2);

    //计算cpu使用率
    cpu = cal_cpuoccupy((CPU_OCCUPY *)&cpu_stat1, (CPU_OCCUPY *)&cpu_stat2);

    return cpu;
}

MEM_PACK *get_memoccupy(void) // get RAM message
{
    FILE *fd;
    double mem_total, mem_used_rate;
    char *result;
    char buff[256];
    MEM_OCCUPY *m = (MEM_OCCUPY *)malloc(sizeof(MEM_OCCUPY));
    ;
    MEM_PACK *p = (MEM_PACK *)malloc(sizeof(MEM_PACK));
    fd = fopen("/proc/meminfo", "r");

    result = fgets(buff, sizeof(buff), fd);
    sscanf(buff, "%s %lu %s\n", m->name, &m->total, m->name2);
    mem_total = m->total;
    result = fgets(buff, sizeof(buff), fd);
    if (result == NULL)
    {
        printf("fgets error\n");
    }
    sscanf(buff, "%s %lu %s\n", m->name, &m->total, m->name2);
    mem_used_rate = (1 - m->total / mem_total) * 100;
    mem_total = mem_total / (1024 * 1024);
    p->total = mem_total;
    p->used_rate = mem_used_rate;
    fclose(fd); //关闭文件fd
    return p;
}

DEV_MEM *get_devmem(void) // get hard disk meeeage
{
    FILE *fp;
    double c, b;
    char a[80], d[80], e[80], f[80], buf[256];
    char *result;
    fp = popen("df", "r");
    result = fgets(buf, 256, fp);
    if (result == NULL)
    {
        printf("fgets error\n");
    }
    double dev_total = 0, dev_used = 0;
    DEV_MEM *dev = (DEV_MEM *)malloc(sizeof(DEV_MEM));
    while (6 == fscanf(fp, "%s %lf %lf %s %s %s", a, &b, &c, d, e, f))
    {
        dev_total += b;
        dev_used += c;
    }
    dev->total = dev_total / 1024 / 1024;
    ;
    dev->used_rate = dev_used / dev_total * 100;
    pclose(fp);
    return dev;
}
MYSQL *initResourceMysql(void)
{
    
    mysql_init(&my_connection);
    if (mysql_real_connect(&my_connection, "localhost", "root", "123456", "monitor", 0, NULL, CLIENT_FOUND_ROWS))
    {
        printf("Connection success\n");
        return &my_connection;
    }
    else
    {
        printf("Connection failed\n");

        if (mysql_errno(&my_connection))
        {
            printf("Connection error %d: %s\n", mysql_errno(&my_connection), mysql_error(&my_connection));
        }
        return NULL;
    }
}
int insertResourceMysql(MYSQL *my_connection, long timestape, int type, double value, long long TEID, long long ip, int is_up)
{
    int result;
    char buff[256];
    // if (ip != -1)
    // {
        sprintf(buff, "insert into resource (timestape, type,value,TEID,ip,is_up) values(%ld,%d,%f,%lld,%lld,%d)", timestape, type, value, TEID, ip, is_up);
    //}
    // else
    // {
    //     sprintf(buff, "insert into resource  (timestape, type,value) values(%ld,%d,%f)", timestape, type, value);
    // }
    result = mysql_query(my_connection, buff);

    if (!result)
    {
        result = (unsigned int)mysql_affected_rows(my_connection);
        printf("Inserted %d rows\n", result);
        /*里头的函数返回受表中影响的行数*/
        return result;
    }
    else
    {
        //分别打印出错误代码及详细信息
        printf("Insert error %d: %s\n", mysql_errno(my_connection), mysql_error(my_connection));
        return -1;
    }
}
void closeMysql(MYSQL *connect)
{
    mysql_close(connect);
}
