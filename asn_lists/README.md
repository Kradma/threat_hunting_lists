# ASN Lists

Esta carpeta publica las salidas CSV del enriquecimiento de reputacion por ASN en un formato listo para consumir desde GitHub.

## Archivos publicados

- `asn_reputation.csv`: dataset completo.
- `asn_reputation_nonzero.csv`: mismo esquema, filtrado a filas con `maliciousness_score > 0`.

Los CSV publicados en esta carpeta no incluyen las lineas de comentario del export nativo, para que puedan cargarse con `externaldata()` en KQL sin preprocesado adicional.

## Como interpretar los resultados

- `asn`: ASN en formato `AS12345`.
- `description`: nombre del operador o descripcion publica del ASN.
- `maliciousness_score`: score operativo de 0 a 100. Cuanto mas alto, mayor senal de actividad maliciosa o abuso sostenido.
- `confidence_score`: confianza del dataset en esa lectura. Ayuda a distinguir senales fuertes de observaciones debiles o poco persistentes.
- `category`: clasificacion principal. Los valores mas accionables suelen ser `hard_block`, `malicious_infrastructure`, `high_risk_abused_hosting` y `high_risk_access_network_abuse`.
- `recommended_action`: sugerencia operativa para ese ASN.
- `observed_bad_ipv4_unique`: numero de IPv4 unicas observadas con senal maliciosa, deduplicadas entre feeds.
- `observed_bad_ipv4_weighted`: intensidad agregada de senal entre feeds. Puede ser mayor que la metrica `unique`.
- `abuse_ratio_unique_pct`: porcentaje estimado del espacio IPv4 del ASN con senal unica observada.
- `distinct_feeds` y `distinct_feed_families`: cuantas fuentes y familias de fuentes apoyan la clasificacion.
- `operator_profile` y `operator_tags`: contexto del tipo de operador para ajustar la interpretacion.
- `spamhaus_asndrop_flag`: el ASN aparece en Spamhaus ASN-DROP.
- `community_bad_asn_flag`: el ASN aparece en una lista comunitaria de riesgo.
- `known_scanner_flag`: ASN conocido por actividad de escaneo de investigacion; no siempre implica actividad maliciosa.
- `ripe_*`: contexto adicional de routing y RPKI desde RIPEstat.
- `first_seen_utc`, `last_seen_utc`, `runs_seen_30d` y `days_observed_30d`: persistencia temporal de la senal.
- `reasons`: resumen textual de por que el ASN quedo clasificado asi.

## Guia rapida de uso

- Para investigacion amplia, usa `asn_reputation.csv`.
- Para deteccion, enrichment o listas de bloqueo blandas, suele ser mejor partir de `asn_reputation_nonzero.csv`.
- Si necesitas una lista mas restrictiva, filtra por `maliciousness_score >= 60` o por categorias concretas.
- Si tu telemetria guarda el ASN como numero, convierte `AS12345` a entero con `toint(replace_string(asn, "AS", ""))`.

## KQL: cargar el CSV desde GitHub

Sustituye `<ORG>`, `<REPO>` y la rama si no usas `main`.

```kusto
let asn_nonzero = externaldata(
    asn:string,
    description:string,
    total_ipv4:long,
    observed_bad_ipv4_unique:long,
    observed_bad_ipv4_weighted:long,
    abuse_ratio_unique_pct:real,
    abuse_ratio_weighted_pct:real,
    distinct_feeds:int,
    distinct_feed_families:int,
    maliciousness_score:int,
    confidence_score:int,
    category:string,
    operator_profile:string,
    operator_tags:string,
    recommended_action:string
)
[@"https://raw.githubusercontent.com/<ORG>/<REPO>/main/asn_lists/asn_reputation_nonzero.csv"]
with (format="csv", ignoreFirstRecord=true);

asn_nonzero
| extend asn_number = toint(replace_string(asn, "AS", ""))
| where maliciousness_score >= 60
| project asn, asn_number, maliciousness_score, confidence_score, category, recommended_action
| order by maliciousness_score desc
```

## KQL: usarlo como lista en una query

Ejemplo generico para cruzar la lista con una tabla que ya tenga un ASN numerico. Cambia `DestinationAsNumber` por el campo ASN de tu tabla.

```kusto
let watched_asns = materialize(
    externaldata(
        asn:string,
        description:string,
        total_ipv4:long,
        observed_bad_ipv4_unique:long,
        observed_bad_ipv4_weighted:long,
        abuse_ratio_unique_pct:real,
        abuse_ratio_weighted_pct:real,
        distinct_feeds:int,
        distinct_feed_families:int,
        maliciousness_score:int,
        confidence_score:int,
        category:string,
        operator_profile:string,
        operator_tags:string,
        recommended_action:string
    )
    [@"https://raw.githubusercontent.com/<ORG>/<REPO>/main/asn_lists/asn_reputation_nonzero.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | extend asn_number = toint(replace_string(asn, "AS", ""))
    | where maliciousness_score >= 60
    | project asn_number, category, recommended_action
);

CommonSecurityLog
| where DestinationAsNumber in (watched_asns | project asn_number)
| join kind=leftouter watched_asns on $left.DestinationAsNumber == $right.asn_number
| project TimeGenerated, DeviceVendor, DeviceProduct, DestinationAsNumber, category, recommended_action
```

## Nota operativa

Los artefactos internos del proceso (`summary`, `state`, `cache`, logs) se mantienen fuera de esta carpeta. Aqui solo se publican los CSV finales orientados a consumo desde GitHub y KQL.
