# Grafana эталонного стенда с плагином источника данных VictoriaLogs.
# Закрытый контур: плагин нельзя скачать при старте, поэтому он ставится при сборке образа (на машине с интернетом),
# а готовый образ переносится в контур вместе с остальными (scripts/export-images -Observability).
# Метрики (VictoriaMetrics) и трассировки (VictoriaTraces) читаются встроенными источниками Prometheus и Jaeger.
ARG GRAFANA_VERSION=13.2.2
FROM grafana/grafana:${GRAFANA_VERSION}

ARG VL_PLUGIN_VERSION=v0.32.0
# Каталог плагинов — вне /var/lib/grafana: там том с данными Grafana, он скрыл бы плагин, установленный в образ.
ENV GF_PATHS_PLUGINS=/opt/grafana/plugins
USER root
RUN mkdir -p /opt/grafana/plugins \
 && grafana cli --pluginsDir /opt/grafana/plugins \
      --pluginUrl "https://github.com/VictoriaMetrics/victorialogs-datasource/releases/download/${VL_PLUGIN_VERSION}/victoriametrics-logs-datasource-${VL_PLUGIN_VERSION}.zip" \
      plugins install victoriametrics-logs-datasource \
 && chown -R 472:0 /opt/grafana/plugins
USER 472
