set(COMPONENT_SRCS "openssl_server_wifi_prov.c")

# Embed the server root certificate into the final binary
#
# (If this was a component, we would set COMPONENT_EMBED_TXTFILES here.)
set(COMPONENT_EMBED_TXTFILES "server.pem" "server.key" "ca.pem")

register_component()
