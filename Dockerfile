FROM php:8.3-apache

# mod_rewrite + tools
RUN a2enmod rewrite \
 && apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
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

# GeoIP country DB — DB-IP Lite (CC-BY), fetched at build; try this month then last month.
RUN mkdir -p /var/www/geo && cd /tmp \
 && ( curl -fsSL -o db.gz "https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz" \
   || curl -fsSL -o db.gz "https://download.db-ip.com/free/dbip-country-lite-$(date -d 'last month' +%Y-%m).mmdb.gz" ) \
 && gunzip -c db.gz > /var/www/geo/country.mmdb \
 && rm -f db.gz \
 && chown -R www-data:www-data /var/www/geo

# Allow .htaccess overrides in the web root
RUN sed -ri 's!AllowOverride None!AllowOverride All!g' /etc/apache2/apache2.conf

EXPOSE 80
