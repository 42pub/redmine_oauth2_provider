# redmine_oauth2_provider

With this plugin Redmine can use OAuth2 protocol for authentication. 
Supported OAuth providers:

* Gerrit (Use [Gerrit plugin](https://github.com/k-muramatsu/gerrit-oauth-provider) as OAuth2 Consumer)


# URLs

- **Authorize**: http://my_redmine_host/oauth2/authorize_client
- **Access Token**: http://my_redmine_host/oauth2/access_token
- **User Information**: http://my_redmine_host/oauth2/user

For add new client: https://my_redmine_host/oauth2/register_client
