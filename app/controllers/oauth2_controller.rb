class Oauth2Controller < ApplicationController 
  before_action :require_login, :except => [ :access_token, :access_user ]
  before_action :require_admin, :only => [:register_app, :create_app, :del_client]

def authorize_app
  # извлекаем все необходимые параметры из запроса
  response_type = request.params['response_type']
  client_id = request.params['client_id']
  redirect_uri = request.params['redirect_uri']
  scope = request.params['scope']
  state = request.params['state']

  # получаем текущего пользователя
  user = User.current
  raise "User not found" if user.nil?

  # сохраняем параметры в переменную @oauth2
  @oauth2 = { client_id: client_id, response_type: response_type, redirect_uri: redirect_uri, scope: scope, state: state, user_id: user.id }

  # если response_type равен 'token' или 'code', это означает, что запросу нужно выполнить редирект
  if @oauth2[:response_type] == 'token' || @oauth2[:response_type] == 'code'
    redirect_to(@oauth2[:redirect_uri])
  end

  respond_to do |format|
    format.html {}
    format.api {}
    format.atom {}
  end
end



  def authorize_app2
    #http://localhost:3000/oauth2/authorize_client?response_type=token&client_id=js6w22mlf06cv4r4en6ka3ac6d4gm3y&redirect_uri=https://owncloud.reichmann-software.com
    @oauth2 = Songkick::OAuth2::Provider.parse(User.current, request.env)
    
    if @oauth2.redirect?  
      redirect_to(@oauth2.redirect_uri, :status => @oauth2.response_status)
    end

    respond_to do |format|
      format.html {}
      format.api {}
      format.atom {}
    end
  end

  def register_app
    @client = Songkick::OAuth2::Model::Client.new
    respond_to do |format|
      format.html {}
      format.api {}
      format.atom {}
    end
  end
 
  def create_app
    @client = Songkick::OAuth2::Model::Client.new({ 'name' => params[:name], 'redirect_uri' => params[:redirect_uri]})
    @client.owner = User.current
    if @client.save
      session[:client_secret] = @client.client_secret
      redirect_to(oauth2_client_show_path(@client.id))
    else
      err_msg = ''
      if @client.errors.any?
        @client.errors.full_messages.each do |message|
          err_msg += "<b class='icon icon-bolt'><i>#{message}</i></b><br />"
        end
      end
      flash[:error] = "#{l(:label_oauth2_create_application_error)}: <br />"
      flash[:error] += err_msg.html_safe
      redirect_to(oauth2_register_client_path)
    end
  end

  def client
    @client = Songkick::OAuth2::Model::Client.find_by_id(params[:id])
    @client_secret = session[:client_secret]
  end

  def clients
    @clients = Songkick::OAuth2::Model::Client.all
  end

  def del_client
    @client = Songkick::OAuth2::Model::Client.find_by_id(params[:id])

    @client.delete
    redirect_to(oauth2_clients_path)
  end

def allow_client
  @auth = Songkick::OAuth2::Provider::Authorization.new(User.current, params)
  if @auth.nil? || @auth.redirect_uri.nil?
    # обработка ошибки, например:
    render json: { error: 'OAuth authorization failed' }, status: :internal_server_error
    return
  end
  if params['allow'] == '1'
    @auth.grant_access!
  else
    @auth.deny_access!
  end
  redirect_to(@auth.redirect_uri,  :status => @auth.response_status)
end

  def access_token
	@auth = Songkick::OAuth2::Model::Authorization.find_by_code(params[:code])
	return halt 400 unless @auth
	response = {
		'access_token'  => @auth.access_token_hash,
		'token_type'    => 'Bearer',
		'expires_in'    => @auth.expires_at,
		'refresh_token' => @auth.refresh_token_hash
	}
	render json: response
  end

  def access_user
	@auth = Songkick::OAuth2::Model::Authorization.find_by_access_token_hash(params[:access_token])
	@user = User.find_by_id(@auth.oauth2_resource_owner_id)
	render json: @user
  end
end

