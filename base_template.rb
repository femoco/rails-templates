generate :nifty_config
generate :nifty_layout

#====================
# PLUGINS
#====================

plugin "authlogic", :git => "git://github.com/binarylogic/authlogic.git"
plugin "acl9", :git => "git://github.com/be9/acl9.git"
plugin "jrails", :git => "git://github.com/aaronchi/jrails.git"
plugin "meta-tags", :git => "git://github.com/kpumuk/meta-tags.git"
plugin "pagination_scope", :git => "git://github.com/genki/pagination_scope.git"
run "svn export https://please.peelmeagrape.net/svn/public/plugins/is_attachment/trunk vendor/plugins/is_attachment"


#====================
# APP
#====================

# authlogic

generate(:nifty_scaffold, "user login:string name:string email:string crypted_password:string password_salt:string persistence_token:string single_access_token:string login_count:integer current_login_at:datetime last_login_at:datetime current_login_ip:string last_login_ip:string new edit")

inside('db/migrate') do
  Dir['*create_users.rb'].each do |m|
    file "db/migrate/#{m}", %q{class CreateUsers < ActiveRecord::Migration
  def self.up
    create_table :users do |t|
      t.string :login, :null => false
      t.string :name
      t.string :email, :null => false
      t.string :crypted_password, :null => false
      t.string :password_salt, :null => false
      t.string :persistence_token, :null => false
      t.string :single_access_token, :null => false
      t.integer :login_count, :null => false, :default => 0
      t.datetime :current_login_at
      t.datetime :last_login_at
      t.string :current_login_ip
      t.string :last_login_ip
      t.timestamps
    end
  end

  def self.down
    drop_table :users
  end
end
}
  end
end

inside('db/migrate') do
  Dir['*create_roles_users.rb'].each do |m|
    file "db/migrate/#{m}", %q{class CreateRolesUsers < ActiveRecord::Migration
  def self.up
    create_table :roles_users, :id => false, :force => true do |t|
      t.integer :user_id
      t.integer :role_id
      t.datetime  :created_at
      t.datetime  :updated_at
    end
  end

  def self.down
    drop_table :roles_users
  end
end
}
  end
end

generate(:session, :user_session)

generate(:nifty_scaffold, "user_session --skip-model login:string password:string new destroy")

file "app/controllers/user_sessions_controller.rb",
%q{class UserSessionsController < ApplicationController
  def new
    @user_session = UserSession.new
  end
  
  def create
    @user_session = UserSession.new(params[:user_session])
    if @user_session.save
      flash[:notice] = "Successfully logged in."
      redirect_to root_url
    else
      render :action => 'new'
    end
  end
  
  def destroy
    @user_session = UserSession.find
    @user_session.destroy
    flash[:notice] = "Successfully logged out."
    redirect_to root_url
  end
end
}

file "app/views/user_sessions/new.html.erb",
%q{<% title "Login" %>

<% form_for @user_session do |f| %>
  <%= f.error_messages %>
  <p>
    <%= f.label :login %><br />
    <%= f.text_field :login %>
  </p>
  <p>
    <%= f.label :password %><br />
    <%= f.password_field :password %>
  </p>
  <p><%= f.submit "Submit" %></p>
<% end %>
}

file "app/controllers/users_controller.rb",
%q{class UsersController < ApplicationController
  def new
    @user = User.new
  end
  
  def create
    @user = User.new(params[:user])
    if @user.save
      # @user.has_role! :admin
      @user.has_role! :member
      flash[:notice] = "Registration successful."
      redirect_to root_url
    else
      render :action => 'new'
    end
  end
end
}

file "app/views/users/_form.html.erb",
%q{<% form_for @user do |f| %>
  <%= f.error_messages %>
  <p>
    <%= f.label :login %><br />
    <%= f.text_field :login %>
  </p>
  <p>
    <%= f.label :email %><br />
    <%= f.text_field :email %>
  </p>
  <p>
    <%= f.label :password %><br />
    <%= f.password_field :password %>
  </p>
  <p>
    <%= f.label :password_confirmation %><br />
    <%= f.password_field :password_confirmation %>
  </p>
  <p><%= f.submit "Submit" %></p>
<% end %>
}

# acl9

generate(:model, "role name:string authorizable_type:string authorizable_id:integer")

inside('db/migrate') do
  Dir['*create_roles.rb'].each do |m|
    file "db/migrate/#{m}", %q{class CreateRoles < ActiveRecord::Migration
  def self.up
    create_table :roles do |t|
      t.string :name, :limit => 40
      t.string :authorizable_type, :limit => 40
      t.integer :authorizable_id

      t.timestamps
    end

		execute "insert into roles (id,name,created_at,updated_at) values (1, 'admin', '2009-07-07 12:00:00', '2009-07-07 12:00:00')"
    execute "insert into roles (id,name,created_at,updated_at) values (2, 'member', '2009-07-07 12:00:00', '2009-07-07 12:00:00')"
    execute "insert into roles (id,name,created_at,updated_at) values (3, 'guest', '2009-07-07 12:00:00', '2009-07-07 12:00:00')"
  end

  def self.down
    drop_table :roles

		execute "delete from roles where name = 'admin'"
    execute "delete from roles where name = 'member'"
    execute "delete from roles where name = 'guest'"
  end
end
}
  end
end

file 'app/models/user.rb',
%q{class User < ActiveRecord::Base
  acts_as_authentic
  acts_as_authorization_subject
  
  has_one :user_image, :dependent => :destroy
  
  accepts_nested_attributes_for :user_image, :reject_if => proc {|attributes| (!attributes.has_key?('uploaded_data') && attributes['source_url'].blank?)}, :allow_destroy => true
  
  validates_presence_of :login
  validates_presence_of :email
end
}

file "app/models/role.rb",
%q{class Role < ActiveRecord::Base
  acts_as_authorization_role
end
}

generate(:migration, "CreateRolesUsers")

inside('db/migrate') do
  Dir['*create_roles_users.rb'].each do |m|
    file "db/migrate/#{m}", %q{class CreateRolesUsers < ActiveRecord::Migration
  def self.up
    create_table :roles_users, :id => false, :force => true do |t|
      t.integer :user_id
      t.integer :role_id
      t.datetime  :created_at
      t.datetime  :updated_at
    end
  end

  def self.down
    drop_table :roles_users
  end
end
}
  end
end

# is_attachment

rake("is_attachment:db_files_table_migration")

generate(:model, "user_image user:references is_attachment_db_file_id:integer base_version_id:integer filename:string version_name:string content_type:string file_size:integer height:integer width:integer image_source_url:integer")

file "app/models/user_image.rb",
%q{class UserImage < ActiveRecord::Base
  belongs_to :user
  
  is_attachment :storage_engine => :db, :image_engine => :rmagick, :image_versions => { :pinkie => :pinkie, :square => :square, :thumb => :thumb, :small => :small, :medium => :medium }, :validate => { :max_file_size => 2.megabyte, :content_type => :image }
  
  def source_url
    image_source_url
  end
  
  def source_url=(url)
    if !url.blank?
      self.uploaded_data = URLTempfile.new(url)
      self.image_source_url = url
    end
  end
  
  def all_version_image_ids
    UserImage.find(:all, :select => "id", :conditions => ["id = #{self.id} or base_version_id = #{self.id}"])
  end
  
  def image_id_for_version(version=nil)
    return is_attachment_db_file_id if version.blank?
  end
  
  def get_all_versions
    UserImage.find(:all, :conditions => ["id = #{self.id} or base_version_id = #{self.id}"])
  end
  
  def get_version(version)
    UserImage.find(:first, :conditions => ["base_version_id = #{self.id} and version_name = ?", version])
  end
  
  def get_id_for_version(version)
    user_image = UserImage.find(:first, :conditions => ["base_version_id = #{self.id} and version_name = ?", version])
    user_image.id
  end
  
  def pinkie(img)
    w = img.columns; h = img.rows
    size = w > h ? h : w
    
    img.crop!(Magick::CenterGravity, size, size, true)
    img.resize!(APP_CONFIG[:pinkie_width], APP_CONFIG[:pinkie_height])
  end
  
  def square(img)
    w = img.columns; h = img.rows
    size = w > h ? h : w
    
    img.crop!(Magick::CenterGravity, size, size, true)
    img.resize!(APP_CONFIG[:square_width], APP_CONFIG[:square_height])
  end
  
  def thumb(img)
    w = img.columns; h = img.rows
    size = w > h ? h : w
    
    img.crop!(Magick::CenterGravity, size, size, true)
    img.resize!(APP_CONFIG[:thumb_width], APP_CONFIG[:thumb_height])
  end
  
  def small(img)
    w = img.columns; h = img.rows
    size = w > h ? h : w
    
    img.crop!(Magick::CenterGravity, size, size, true)
    img.resize!(APP_CONFIG[:small_width], APP_CONFIG[:small_height])
  end
  
  def medium(img)
    # RMAGICK TIPS
    # extent
    # image.extent(width, height, x=0, y=0) -> anImage
    # width
    # The width of the new image
    # height
    # The heigth of the new image
    # x, y
    # The upper-left corner of the new image is positioned at -x, -y.
    img.change_geometry("#{APP_CONFIG[:medium_width]}x#{APP_CONFIG[:medium_height]}") { |cols,rows,image| image.resize!(cols,rows)}
    # img.change_geometry("#{APP_CONFIG['medium_width']}x#{APP_CONFIG['medium_height']}") { |cols,rows,image| image.resize!(cols,rows)}
    
    w = img.columns
    h = img.rows
    
    if w > h
      # w : 140 = h : y
      # w*y = 140xh
      # y = 140 * h / w
      y = APP_CONFIG[:medium_width] * h / w
      # y = (140-y)/2
      y = (APP_CONFIG[:medium_width] - y) / 2
      x = 0
    end
    if w < h
      # h : 140 = w : x
      # 140*w = h*x
      # x = 140 * w / h
      x = APP_CONFIG[:medium_width] * w / h
      # x = (140-x)/2
      x = (APP_CONFIG[:medium_width] - x) / 2
      y = 0
    end

    img.extent(APP_CONFIG[:medium_width],APP_CONFIG[:medium_height],-x,-y)
  end
  
  def before_create
    if self.is_base_version?
      case self.content_type
      when 'image/jpeg'
        ext = '.jpg'
      when 'image/pjpeg'
        ext = '.jpg'
      when 'image/gif'
        ext = '.gif'
      when 'image/png'
        ext = '.png'
      when 'image/x-png'
        ext = '.png'
      end
      # self.filename=('new_filename'+ext)
      self.filename=(getRandomString(10)+ext)
    end
    # self.filename=('new_filename')
  end
  
  def after_save
    # self.clear_existing_temp_file
    # unless self.temp_path.nil?
    #   FileUtils.rm_rf(File.dirname(self.temp_path))
    #   self.temp_path = nil
    # end
  end
  
  def getRandomString (length = 8)
    source=("a".."z").to_a + ("A".."Z").to_a + (0..9).to_a + ["_","-","."]
    key=""
    length.times{ key+= source[rand(source.size)].to_s }
    return key
  end
end
}

generate(:controller, "user_images show")

file "app/controllers/user_images_controller.rb",
%q{class UserImagesController < ApplicationController
  caches_page :original, :medium, :thumb, :square
  
  def show
    @user = User.find(params[:user_id])
    @user_image = @user.user_image
    respond_to do |format|
      format.jpg
      format.png
      format.gif
    end
  end
  
  def pinkie
    @user = User.find(params[:user_id])
    @user_image = @user.user_image.get_version('pinkie')

    respond_to do |format|
      format.jpg { render :template => 'user_images/show.jpg' }
      format.png { render :template => 'user_images/show.png' }
      format.gif { render :template => 'user_images/show.gif' }
    end
  end
  
  def square
    @user = User.find(params[:user_id])
    @user_image = @user.user_image.get_version('square')

    respond_to do |format|
      format.jpg { render :template => 'user_images/show.jpg' }
      format.png { render :template => 'user_images/show.png' }
      format.gif { render :template => 'user_images/show.gif' }
    end
  end
  
  def thumb
    @user = User.find(params[:user_id])
    @user_image = @user.user_image.get_version('thumb')

    respond_to do |format|
      format.jpg { render :template => 'user_images/show.jpg' }
      format.png { render :template => 'user_images/show.png' }
      format.gif { render :template => 'user_images/show.gif' }
    end
  end
  
  def small
    @user = User.find(params[:user_id])
    @user_image = @user.user_image.get_version('small')

    respond_to do |format|
      format.jpg { render :template => 'user_images/show.jpg' }
      format.png { render :template => 'user_images/show.png' }
      format.gif { render :template => 'user_images/show.gif' }
    end
  end
  
  def medium
    @user = User.find(params[:user_id])
    @user_image = @user.user_image.get_version('medium')

    respond_to do |format|
      format.jpg { render :template => 'user_images/show.jpg' }
      format.png { render :template => 'user_images/show.png' }
      format.gif { render :template => 'user_images/show.gif' }
    end
  end
  
  def original
    @user = User.find(params[:user_id])
    @user_image = @user.user_image

    respond_to do |format|
      format.jpg { render :template => 'user_images/show.jpg' }
      format.png { render :template => 'user_images/show.png' }
      format.gif { render :template => 'user_images/show.gif' }
    end
  end
end
}

file "app/views/user_images/show.gif.erb",
%q{<%= @user_image.is_attachment_db_file.data %>
}

file "app/views/user_images/show.jpg.erb",
%q{<%= @user_image.is_attachment_db_file.data %>
}

file "app/views/user_images/show.png.erb",
%q{<%= @user_image.is_attachment_db_file.data %>
}

generate(:controller, "account/settings edit")
generate(:controller, "account/picture edit")
generate(:controller, "account/password edit")

file "app/controllers/account/settings_controller.rb",
%q{class Account::SettingsController < ApplicationController
  before_filter :require_user
  
  def edit
    @user = current_user
  end
  
  def update
    @user = current_user
    if @user.update_attributes(params[:user])
      flash[:notice] = "Successfully updated settings."
      redirect_to account_settings_path
    else
      render :action => 'edit'
    end
  end
end
}

file "app/views/account/settings/edit.html.erb",
%q{<ul id="account_nav">
	<li><%= link_to('settings', account_settings_path) %></li>
	<li><%= link_to('password', account_password_path) %></li>
	<li><%= link_to('picture', account_picture_path) %></li>
</ul>

<% form_for @user, :url => {:controller => 'account/settings', :action => 'update'}, :method => 'put', :html => {:class => 'account'} do |f| -%>
  <%= f.error_messages %>
	<p>
		<%= f.label :login, "Login" %><br />
		<%= f.text_field :login, :class => 'text' %>
	</p>
	<p>
		<%= f.label :name, "Name" %><br />
		<%= f.text_field :name, :class => 'text' %>
	</p>
	<p>
		<%= f.label :email, "Email" %><br />
		<%= f.text_field :email, :class => 'text' %>
	</p>
	<p>
		<%= f.submit "Submit", :disable_with => 'Submiting...' %>
	</p>
<% end -%>
}

file "app/controllers/account/picture_controller.rb",
%q{class Account::PictureController < ApplicationController
  before_filter :require_user
  
  def edit
    @user = current_user
    @user_image = @user.user_image ||= @user.build_user_image
  end

  def update
    @user = current_user
    if @user.update_attributes(params[:user])
      flash[:notice] = "Successfully updated picture."
      redirect_to account_picture_path
    else
      render :action => 'edit'
    end
  end
end
}

file "app/views/account/picture/edit.html.erb",
%q{<ul id="account_nav">
	<li><%= link_to('settings', account_settings_path) %></li>
	<li><%= link_to('password', account_password_path) %></li>
	<li><%= link_to('picture', account_picture_path) %></li>
</ul>

<% form_for @user, :url => {:controller => 'account/picture', :action => 'update'}, :method => 'put', :html => {:multipart => true, :class => 'account'} do |f| -%>
  <%= f.error_messages %>
	<%- if current_user.user_image.filename -%>
		<%= image_tag(square_user_user_image_path(current_user)) %>
	<%- else -%>
		<%= image_tag('default_square.gif') %>
	<%- end -%>
	
	<%- f.fields_for :user_image do |user_image_form| -%>
		<p>
			<%= user_image_form.label :uploaded_data, "Uploaded Data" %><br />
			<%= user_image_form.file_field :uploaded_data %>
		</p>
		<p>
			<%= user_image_form.check_box :_delete %>
			<%= user_image_form.label '_delete', "Delete picture" %>
		</p>
	<%- end -%>
	
	<p>
		<%= f.submit "Submit", :disable_with => 'Submiting...' %>
	</p>
<% end -%>
}

file "app/controllers/account/password_controller.rb",
%q{class Account::PasswordController < ApplicationController
  
  before_filter :require_user
  
  def edit
    @user = current_user
  end

  def update
    @user = current_user
    if @user.update_attributes(params[:user])
      flash[:notice] = "Successfully updated password."
      redirect_to account_password_path
    else
      render :action => 'edit'
    end
  end
end
}

file "app/views/account/password/edit.html.erb",
%q{<ul id="account_nav">
	<li><%= link_to('settings', account_settings_path) %></li>
	<li><%= link_to('password', account_password_path) %></li>
	<li><%= link_to('picture', account_picture_path) %></li>
</ul>

<% form_for @user, :url => {:controller => 'account/password', :action => 'update'}, :method => 'put', :html => {:class => 'account'} do |f| -%>
  <%= f.error_messages %>
	<p>
		<%= f.label :password, "Password" %><br />
		<%= f.password_field :password, :class => 'text' %>
	</p>
	<p>
		<%= f.label :password_confirmation, "Password Confirmation" %><br />
		<%= f.password_field :password_confirmation, :class => 'text' %>
	</p>
	<p>
		<%= f.submit "Submit", :disable_with => 'Submiting...' %>
	</p>
<% end -%>
}

# admin consoles
generate(:controller, "admin/root index")
generate(:controller, "admin/users index")

file "app/controllers/admin/root_controller.rb",
%q{class Admin::RootController < ApplicationController
  access_control do
    allow :admin
  end
  
  def index
  end
end
}

file "app/views/admin/root/index.html.erb",
%q{<ul id="account_nav">
	<li><%= link_to('top', admin_root_path) %></li>
	<li><%= link_to('users', admin_users_path) %></li>
</ul>
}

file "app/controllers/admin/users_controller.rb",
%q{class Admin::UsersController < ApplicationController
  access_control do
    allow :admin
  end
  
  def index
  end
end
}

file "app/views/admin/users/index.html.erb",
%q{<ul id="account_nav">
	<li><%= link_to('top', admin_root_path) %></li>
	<li><%= link_to('users', admin_users_path) %></li>
</ul>
}

# create a session table
rake('db:sessions:create')

# MySQL specific
if yes?("Do you want to use MySQL? (yes/no)")
  project_name = ask("What is a project name for this app?")
  username = ask("Please input MySQL username")
  password = ask("Please input MySQL password.")
  
  file "config/database.yml", %Q{development:
  adapter: mysql
  encoding: utf8
  reconnect: false
  database: #{project_name}_development
  pool: 5
  username: #{username}
  password: #{password}
  socket: /tmp/mysql.sock

# Warning: The database defined as "test" will be erased and
# re-generated from your development database when you run "rake".
# Do not set this db to the same as development or production.
test:
  adapter: mysql
  encoding: utf8
  reconnect: false
  database: #{project_name}_test
  pool: 5
  username: #{username}
  password: #{password}
  socket: /tmp/mysql.sock

production:
  adapter: mysql
  encoding: utf8
  reconnect: false
  database: #{project_name}_production
  pool: 5
  username: #{username}
  password: #{password}
  socket: /tmp/mysql.sock
}
  
  inside('db/migrate') do
    Dir['*add_is_attachment_db_files_table.rb'].each do |m|
      file "db/migrate/#{m}", %q{class AddIsAttachmentDbFilesTable < ActiveRecord::Migration
  def self.up
    create_table :is_attachment_db_files do |t|
      t.column :data, "longblob"
    end
  end

  def self.down
    drop_table :is_attachment_db_files
  end
end
}
    end
  end
  
  run "rm db/development.sqlite3"
end






# commons

generate(:controller, "root index")

# add lib/form_encoder.rb
file "lib/form_encoder.rb", %q{module FormEncoder
  def self.encode(parameters, prefix = "")
    case parameters
    when Hash; encode_hash(parameters, prefix)
    when Array; encode_array(parameters, prefix)
    else "#{prefix }=#{CGI.escape(parameters.to_s) }"
    end
  end

private
  def self.encode_hash(hash, prefix)
    hash.inject([]) do |result, (key, value)|
      key = CGI.escape(key.to_s)
      result << encode(value, prefix.empty? ? key : "#{ prefix }[#{ key }]")
    end.join('&')
  end

  def self.encode_array(array, prefix)
    array.inject([]) do |result, value|
      result << encode(value, "#{prefix }[]")
    end.join('&')
  end
end

# FormEncoder.encode :foo => {:bar => [1, 2], :baz => "Rails"}
# #=> "foo[baz]=Rails&foo[bar][]=1&foo[bar][]=2"
# 
# CGIMethods.parse_query_parameters(
#   "foo[baz]=Rails&foo[bar][]=1&foo[bar][]=2")
# #=> {"foo"=>{"baz"=>"Rails", "bar"=>["1", "2"]}}
}

# add lib/URLTempfile.rb
file "lib/URLTempfile.rb", %q{# require 'mime/types'
require 'openssl'
require 'open-uri'


# This class provides a Paperclip plugin compliant interface for an "upload" file
# where that uploaded file is actually coming from a URL.  This class will download
# the file from the URL and then respond to the necessary methods for the interface,
# as required by Paperclip so that the file can be processed and managed by 
# Paperclip just as a regular uploaded file would.
#
class URLTempfile < Tempfile
  attr :content_type
  
  def initialize(url)
    @url = URI.parse(url)
    
    # see if we can get a filename
    raise "Unable to determine filename for URL uploaded file." unless original_filename

    begin
      # HACK to get around inability to set VERIFY_NONE with open-uri
      old_verify_peer_value = OpenSSL::SSL::VERIFY_PEER
      OpenSSL::SSL.const_set("VERIFY_PEER", OpenSSL::SSL::VERIFY_NONE)
      
      super('urlupload')
      Kernel.open(url) do |file|
        @content_type = file.content_type
        raise "Unable to determine MIME type for URL uploaded file." unless content_type
      
        self.write file.read
        self.flush
      end
    ensure
      OpenSSL::SSL.const_set("VERIFY_PEER", old_verify_peer_value)
    end
  end
  
  def original_filename
    # Take the URI path and strip off everything after last slash, assume this
    # to be filename (URI path already removes any query string)
    match = @url.path.match(/^.*\/(.+)$/)
    return (match ? match[1] : nil)
  end
end
}

# edit app/helpers/application_helper.rb to use with pagination_scope
file "app/helpers/application_helper.rb", %q{# Methods added to this helper will be available to all templates in the application.
module ApplicationHelper
  
  def paginate_with_path(model, path, options = {})
    window     = options[:window] || 5
    left       = options[:left] || 2
    right      = options[:right] || 2
    prev_label = options[:prev] || '&laquo; Prev'
    next_label = options[:next] || 'Next &raquo;'
    truncate   = options[:truncate] || '...'
    page       = model.page
    num_pages  = model.num_pages
    pages      = model.pages(window, left, right)
    return if pages.empty?

    span = proc do |*args|
      content_tag(:span, args[0].to_s, :class => (args[1]||"disabled"))
    end
    items = []
    
    items << ((page > 1) ? link_to(prev_label,
      path+'?'+FormEncoder.encode(:page => page - 1), :class => :prev, :rel => "prev") :
      span.call(prev_label))
    
    items += pages.map{|i|
      if i.nil?
        truncate
      elsif i == page
        span.call(i, "current")
      else
        query = FormEncoder.encode :page => i
        link_to i, path+'?'+query
      end
    }

    items << ((page < num_pages) ? link_to(next_label,
      path+'?'+FormEncoder.encode(:page => page + 1), :class => :older, :rel => "next") :
      span.call(next_label))

    content_tag(:div, items.join("\n"), :class => "pagination")
  end
end
}

# modiry config/initializers/mime_types.rb to add jpg, png, and gif
file "config/initializers/mime_types.rb", %q{# Be sure to restart your server when you modify this file.

# Add new mime types for use in respond_to blocks:
# Mime::Type.register "text/richtext", :rtf
# Mime::Type.register_alias "text/html", :iphone
Mime::Type.register_alias "image/jpeg", :jpg
Mime::Type.register_alias "image/png", :png
Mime::Type.register_alias "image/gif", :gif
}

file "app/controllers/application_controller.rb",
%q{# Filters added to this controller apply to all controllers in the application.
# Likewise, all the methods added will be available for all controllers.

class ApplicationController < ActionController::Base
  rescue_from "Acl9::AccessDenied", :with => :access_denied
  helper :all # include all helpers, all the time
  protect_from_forgery # See ActionController::RequestForgeryProtection for details

  # Scrub sensitive parameters from your log
  # filter_parameter_logging :password
  
  helper_method :current_user, :current_user_session
  filter_parameter_logging :password, :password_confirmation
  
  private
  def current_user_session
    return @current_user_session if defined?(@current_user_session)
    @current_user_session = UserSession.find
  end
  
  def current_user
    return @current_user if defined?(@current_user)
    @current_user = current_user_session && current_user_session.record
  end
  
  def require_user
    unless current_user
      store_location
      flash[:notice] = "You must be logged in to access this page."
      redirect_to new_user_session_url
      return false
    end
  end
  
  def require_no_user
    if current_user
      store_location
      flash[:notice] = "You must be logged out to access this page."
      redirect_to root_url
      # redirect_to home_url
      return false
    end
  end
  
  def store_location
    session[:return_to] = request.request_uri
  end
  
  def redirect_back_or_default(default)
    redirect_to(session[:return_to] || default)
    session[:return_to] = nil
  end
  
  def access_denied
    if current_user
      render :template => 'root/access_denied'
    else
      flash[:notice] = "Access denied. Try to log in first."
      redirect_to login_path
    end
  end
end
}

file 'app/views/root/access_denied.html.erb',
%q{<div class="error">
	Access denied.
</div>
}

file 'app/views/layouts/application.html.erb',
%q{<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
  <head>
    <title><%= h(yield(:title) || "Untitled") %></title>
    <%= stylesheet_link_tag 'application' %>
    <%= yield(:head) %>
  </head>
  <body>
    <div id="container">
			<div id="user_nav">
				<%- if current_user -%>
					<%= link_to "Edit Profile", account_settings_path %> |
					<%= link_to "Logout", logout_path %>
				<%- else -%>
					<%= link_to "Register", signup_path %> |
					<%= link_to "Login", login_path %>
				<%- end -%>
			</div>
      <%- flash.each do |name, msg| -%>
        <%= content_tag :div, msg, :id => "flash_#{name}" %>
      <%- end -%>

      <%- if show_title? -%>
        <h1><%=h yield(:title) %></h1>
      <%- end -%>

      <%= yield %>
    </div>
  </body>
</html>
}

file 'public/stylesheets/application.css',
%q{body {
  background-color: #4B7399;
  font-family: Verdana, Helvetica, Arial;
  font-size: 14px;
}

a img {
  border: none;
}

a {
  color: #0000FF;
}

.clear {
  clear: both;
  height: 0;
  overflow: hidden;
}

#container {
  width: 75%;
  margin: 0 auto;
  background-color: #FFF;
  padding: 20px 40px;
  border: solid 1px black;
  margin-top: 20px;
}

#flash_notice, #flash_error {
  padding: 5px 8px;
  margin: 10px 0;
}

#flash_notice {
  background-color: #CFC;
  border: solid 1px #6C6;
}

#flash_error {
  background-color: #FCC;
  border: solid 1px #C66;
}

.fieldWithErrors {
  display: inline;
}

#errorExplanation {
  width: 400px;
  border: 2px solid #CF0000;
  padding: 0px;
  padding-bottom: 12px;
  margin-bottom: 20px;
  background-color: #f0f0f0;
}

#errorExplanation h2 {
  text-align: left;
  font-weight: bold;
  padding: 5px 5px 5px 15px;
  font-size: 12px;
  margin: 0;
  background-color: #c00;
  color: #fff;
}

#errorExplanation p {
  color: #333;
  margin-bottom: 0;
  padding: 8px;
}

#errorExplanation ul {
  margin: 2px 24px;
}

#errorExplanation ul li {
  font-size: 12px;
  list-style: disc;
}

#user_nav {
	float:	right;
}
}

file 'config/app_config.yml',
%q{development:
  domain: localhost:3000
  site_title: PLEASE_CHANGE
  site_title_prefix:  ' | '
  per_page_short: 7
  per_page_medium:  14
  per_page_long:  30
  content_trim_length:  90
  pinkie_width: 24
  pinkie_height:  24
  square_width: 48
  square_height:  48
  thumb_width:  75
  thumb_height: 75
  small_width:  150
  small_height: 150
  medium_width: 500
  medium_height:  500

test:
  domain: localhost:3000
  site_title: PLEASE_CHANGE
  site_title_prefix:  ' | '
  per_page_short: 7
  per_page_medium:  14
  per_page_long:  30
  content_trim_length:  90
  pinkie_width: 24
  pinkie_height:  24
  square_width: 48
  square_height:  48
  thumb_width:  75
  thumb_height: 75
  small_width:  150
  small_height: 150
  medium_width: 500
  medium_height:  500

production:
  domain: www.jimocast.net
  site_title: PLEASE_CHANGE
  site_title_prefix:  ' | '
  per_page_short: 7
  per_page_medium:  14
  per_page_long:  30
  content_trim_length:  90
  pinkie_width: 24
  pinkie_height:  24
  square_width: 48
  square_height:  48
  thumb_width:  75
  thumb_height: 75
  small_width:  150
  small_height: 150
  medium_width: 500
  medium_height:  500
}

# modiry routes
file "config/routes.rb",
%q{ActionController::Routing::Routes.draw do |map|
  map.signup "signup", :controller => "users", :action => "new"
  map.logout 'logout', :controller => 'user_sessions', :action => 'destroy'
  map.login 'login', :controller => 'user_sessions', :action => 'new'
  map.resources :user_sessions

  map.resources :users do |user|
    user.resource :user_image, :member => {:original => [:get], :medium => [:get], :thumb => [:get], :square => [:get]}, :only => [:original, :medium, :thumb, :square]
  end
  
  map.namespace(:account) do |account|
    account.settings 'settings', :controller => 'settings', :action => 'edit'
    account.password 'password', :controller => 'password', :action => 'edit'
    account.picture 'picture', :controller => 'picture', :action => 'edit'
  end
  
  map.namespace(:admin) do |admin|
    admin.root :controller => 'root'
    admin.resources :users
  end

  map.root :controller => 'root'

  map.connect ':controller/:action/:id'
  map.connect ':controller/:action/:id.:format'
end
}

rake('db:create')
rake('db:migrate')


#====================
# CLEAN UP
#====================

# Delete unnecessary files
run "rm public/index.html"
run "rm public/favicon.ico"
run "rm app/views/user_images/show.html.erb"

# ====================
# FINALIZE
# ====================

# Set up git repository
git :init

# Set up .gitignore files
file ".gitignore", <<-END
.DS_Store
log/*.log
tmp/**/*
db/*.sqlite3
END

run "touch tmp/.gitignore log/.gitignore vendor/.gitignore lib/.gitignore"
run "cp config/database.yml config/example_database.yml"

git :add => "."
git :commit => "-m 'initial commit'"

