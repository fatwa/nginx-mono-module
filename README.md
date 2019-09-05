# nginx-mono-module
一个 nginx 的 .net 扩展。

## 使用说明，以 CentOS 7 为例

### 安装 mono
```cmd
rpmkeys --import "http://pool.sks-keyservers.net/pks/lookup?op=get&search=0x3fa7e0328081bff6a14da29aa6a19b38d3d831ef"
su -c 'curl https://download.mono-project.com/repo/centos7-stable.repo | tee /etc/yum.repos.d/mono-centos7-stable.repo'
yum install mono-devel libmono-2_0-dev
```

### 编译 Cnaws.Web.Hodting 项目
把生成的 Cnaws.Web.Hodting.dll 放到 /usr/lib/cnaws/ 目录下。
```cmd
gacutil -i /usr/lib/cnaws/Cnaws.Web.Hodting.dll
```

### 编译 nginx (根据实际情况自行修改)
```cmd
./auto/configure --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/cache/nginx/client_temp --http-proxy-temp-path=/var/cache/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/nginx/scgi_temp --pid-path=/var/run/nginx.pid --user=nginx --group=nginx --with-http_ssl_module --add-module=/usr/local/src/nginx/nginx-mono-module
make
make install
```

### 把 nginx.service 文件放到 /usr/lib/systemd/system/ 目录下
```cmd
systemctl enable nginx
systemctl start nginx
```
可能会需要为 nginx 创建某些文件夹或设置文件夹权限。

### nginx 配置
```fs
user  nginx nginx;

...

http {
    
	...

	mono_lib_and_etc  /usr/lib /etc /usr/lib/cnaws;

	...

	server {
        listen       80;
        server_name  mydomain;

        mono_root_and_vroot /var/www/site /;
    }

	server {
        listen       80;
        server_name  mydomain;

        location / {
            mono_root_and_vroot /var/www/site /;
        }

		location /uploads/ {
            root /var/www/livechat;
        }

		...

    }

	...

}
```