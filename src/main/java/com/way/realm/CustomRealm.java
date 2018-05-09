package com.way.realm;



import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;
/*import org.junit.Before;
import org.junit.Test;*/

import com.alibaba.druid.pool.DruidDataSource;
import com.alibaba.druid.pool.DruidPooledConnection;

/**
 * 自定义Realm要继承AuthorizingRealm并实现两个抽象方法
 * @author Administrator
 *
 */
public class CustomRealm extends AuthorizingRealm {
	
	public static void main(String[] args) {
		//Md5Hash md5Hash = new Md5Hash("123456");
		//加盐
		Md5Hash md5Hash = new Md5Hash("123456","Salt");
		System.out.println(md5Hash.toString());
		
	}
	
	
	

	@Override
	//授权
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
		// TODO Auto-generated method stub
		//1.从主体传过来的授权信息 获得角色信息
		String userName = (String) principalCollection.getPrimaryPrincipal();
		
		
		//2.通过用户名到数据库获取角色与权限凭证
		Set<String> roles = getRolesByUserName(userName);
		if(roles==null) {
			return null;
		}
		
		Set<String> permissions = getPermissionsByUserName(userName);
		if(permissions==null) {
			return null;
		}
		
		//3.设置并返回SimpleAuthorizationInfo
		SimpleAuthorizationInfo  simpleAuthorizationInfo = new SimpleAuthorizationInfo();
		simpleAuthorizationInfo.setRoles(roles);
		simpleAuthorizationInfo.setStringPermissions(permissions);
		
		return simpleAuthorizationInfo;
	}



	@Override
	//认证
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
		// TODO Auto-generated method stub
		//1.从主体传过来的认证信息 获得用户名
		String userName = (String) authenticationToken.getPrincipal();
		
		
		//2.通过用户名到数据库获取认证信息
		String password = getPasswordByUserName(userName);
		if(password==null) {
			return null;
		}
		
		
		//3.设置并返回SimpleAuthenticationInfo
		
		
		
		SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(userName, password, "customeRealm");
		//更安全 返回前加盐
		
		authenticationInfo.setCredentialsSalt(ByteSource.Util.bytes("Salt"));
		
		
		
		return authenticationInfo;
	}
	
	
	
	
	
	
	private String getPasswordByUserName(String username) {
		String sql = "select password from test_user where user_name = ?";
		
		try {
			Connection connection = dataSource.getConnection();
			PreparedStatement statement = connection.prepareStatement(sql);
			statement.setString(1, username);
			ResultSet resultSet = statement.executeQuery();
			if(resultSet.next()) {
				String password = resultSet.getString(1);
				if(password==null) {
					return null;
				}else {
					return password;
				}
			}
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		return null;
	}
	
	
	private Set<String> getRolesByUserName(String username) {
		String sql = "select role_name from user_roles where username = ?";
		
		try {
			Connection connection = dataSource.getConnection();
			PreparedStatement statement = connection.prepareStatement(sql);
			statement.setString(1, username);
			ResultSet resultSet = statement.executeQuery();
			if(resultSet.next()) {
				String roles = resultSet.getString(1);
				String[] strings = roles.split(",");
				Set<String> roles_set =  new HashSet<String>();
				for (String role : strings) {
					System.out.println("role"+role);
					roles_set.add(role);
				}
				
				
				if(roles_set!=null&&roles_set.size()>0) {
					return roles_set;
				}else {
					return null;
				}
			}
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		return null;
	}
	
	
	private Set<String> getPermissionsByUserName(String username) {
		String sql = "SELECT rp.permission from users u  , user_roles ur ,roles_permissions rp where u.username = ur.username and ur.role_name = rp.role_name and u.username= ?";
		
		try {
			Connection connection = dataSource.getConnection();
			PreparedStatement statement = connection.prepareStatement(sql);
			statement.setString(1, username);
			ResultSet resultSet = statement.executeQuery();
			if(resultSet.next()) {
				String permissions = resultSet.getString(1);
				String[] strings = permissions.split(",");
				Set<String> permission_set =  new HashSet<String>();
				for (String permission : strings) {
					System.out.println("permission"+permission);
					permission_set.add(permission);
				}
				
				
				if(permission_set!=null&&permission_set.size()>0) {
					return permission_set;
				}else {
					return null;
				}
			}
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		return null;
	}
	
	
	DruidDataSource dataSource = new DruidDataSource();
	
	{
		dataSource.setUrl("jdbc:mysql://localhost:3306/test");
		dataSource.setUsername("root");
		dataSource.setPassword("root");
		
	}
	
	
	
	/*@Test*/
	public void testAuthentication(){
		
	
		
		
		
		//自定义realm 

		CustomRealm customRealm =  new CustomRealm();
		
		
		//1.构建 SecurityManager环境
		DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
		
		
		//把realm设置到环境中
		defaultSecurityManager.setRealm(customRealm);
		
		
		//1.1   加密
		HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
		//加密方式
		matcher.setHashAlgorithmName("md5");
		//加密次数
		matcher.setHashIterations(1);

		
		
		
		customRealm.setCredentialsMatcher(matcher);
		
		
		
		//2.主体提交认证请求
		SecurityUtils.setSecurityManager(defaultSecurityManager);
		Subject subject = SecurityUtils.getSubject();
		
		UsernamePasswordToken token = new UsernamePasswordToken("Way", "123456");
		//登陆
		subject.login(token);
		
		System.out.println("是否认证"+subject.isAuthenticated());
		
		//认证完后验证角色
		subject.checkRole("admin");
		
		//是否有用户删除权限 		//!!!注意 jdbcRealm要设置权限验证的开关
		subject.checkPermission("user:delete");
		subject.checkPermission("user:update");
		//可以验证多个角色
		//subject.checkRoles("admin","user");
		
		//登出
/*		
		subject.logout();
		
		System.out.println("是否认证"+subject.isAuthenticated());*/
	}



}
