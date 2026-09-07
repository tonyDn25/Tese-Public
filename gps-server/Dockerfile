FROM openresty/openresty:1.25.3.1-alpine

RUN apk add --no-cache openssl openssl-dev perl curl git && \
    opm get fffonion/lua-resty-openssl

RUN mkdir -p /etc/nginx/lua /etc/nginx/keys /etc/nginx/certs /etc/nginx/html/static

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/sign_page.lua /etc/nginx/lua/sign_page.lua
COPY lua/sign_pdf.lua /etc/nginx/lua/sign_pdf.lua
COPY certs/ /etc/nginx/certs/
COPY html/ /etc/nginx/html/

# The private key is NOT baked into the image.
# Mount it at runtime: -v /path/to/nginx_private.pem:/etc/nginx/keys/nginx_private.pem:ro
# Both sign_page.lua and sign_pdf.lua read from /etc/nginx/keys/nginx_private.pem.

EXPOSE 443
CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
