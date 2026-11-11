FROM php:8.3-apache

# mod_rewrite + tools (unzip is required by composer to extract dist packages)
RUN a2enmod rewrite \
 && apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates unzip \
 && rm -rf /var/lib/apt/lists/*

# bcmath helps the pure-PHP MaxMind reader on some platforms
RUN docker-php-ext-install bcmath

# Composer deps (geoip2 reader)
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
WORKDIR /var/www
COPY composer.json /var/www/composer.json
RUN composer install --no-dev --no-interaction --prefer-dist --no-progress

# Application
COPY app/public/  /var/www/html/
COPY app/private/ /var/www/private/

# GeoIP country DB — DB-IP Lite (CC-BY). Non-fatal: if the download ever fails,
# the build still succeeds and the app falls back to ip-api.com at runtime.
RUN mkdir -p /var/www/geo && cd /tmp \
 && ( curl -fsSL -o db.gz "https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz" \
   || curl -fsSL -o db.gz "https://download.db-ip.com/free/dbip-country-lite-$(date -d 'last month' +%Y-%m).mmdb.gz" ) \
 && gunzip -c db.gz > /var/www/geo/country.mmdb \
 && rm -f db.gz \
 && chown -R www-data:www-data /var/www/geo \
 || echo "WARN: GeoIP DB not bundled at build; runtime will use ip-api.com fallback"

# Allow .htaccess overrides in the web root
RUN sed -ri 's!AllowOverride None!AllowOverride All!g' /etc/apache2/apache2.conf

# Persistent data dir (whitelist + leads) + entrypoint that keeps it writable
# after Coolify mounts the volume over it at runtime.
RUN mkdir -p /var/www/data && chown -R www-data:www-data /var/www/data \
 && printf '#!/bin/sh\nmkdir -p /var/www/data\nchown -R www-data:www-data /var/www/data\nexec apache2-foreground\n' > /usr/local/bin/tbav-entry \
 && chmod +x /usr/local/bin/tbav-entry
CMD ["tbav-entry"]

EXPOSE 80
