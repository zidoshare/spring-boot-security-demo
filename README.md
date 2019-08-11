# 通过官方demo简析spring security原理

请注意，本次简析尽可能的照顾了初学者，也会循序渐进的解释很多spring相关机制，但是仍然希望读者能对spring有一定的了解，个人水平有限，很难面面俱到。

# 项目构建

戳>>>>>>>[官方文档](https://spring.io/guides/gs/securing-web/)

戳>>>>>>>[我的示例](https://github.com/zidoshare/spring-boot-security-demo)

# 从spring boot的逻辑里看spring security如何生效

首先查看主要的[WebSecurityConfig](https://github.com/zidoshare/spring-boot-security-demo/blob/master/src/main/java/site/zido/demo/common/WebSecurityConfig.java)类

如何实现spring security的自动配置呢？关键就在于`@EnableWebSecurity`注解，我们查看该注解的源代码：
```java
@Retention(value = java.lang.annotation.RetentionPolicy.RUNTIME)
@Target(value = { java.lang.annotation.ElementType.TYPE })
@Documented
@Import({ WebSecurityConfiguration.class,
		SpringWebMvcImportSelector.class,
		OAuth2ImportSelector.class })
@EnableGlobalAuthentication
@Configuration
public @interface EnableWebSecurity {

	boolean debug() default false;
}
```

其中涉及到spring中的自动配置的注解为`@Import`注解，同样的，我们在`@EnableGlobalAuthentication`注解源代码中也能看到这个`@Import`注解。
在`@Import`源码中，能够看到实际上它的作用很简单，只有一句话：**表示要导入的一个或多个{@link Configuration @Configuration}类**，不用再继续追究spring如何实现，通过这个注释能够知道，spring通过`@import`注解能使其他的配置类生效即可。
同时在更详细的注释里还能看到可以**使ImportSelector以及ImportBeanDefinitionRegistrar生效**。

* ImportSelector接口只有一个方法，是`String[] selectImports(AnnotationMetadata importingClassMetadata)`，回调使被导入的相关mata数据，然后用户可通过这些mata数据，动态的返回任何Configuration
* ImportBeanDefinitionRegistrar接口仍然只有一个方法，它用来更灵活的去选择注册bean。

WebSecurityConfiguration类是一个自动配置类放在后面讲，先查看这两个ImportSelector，看看他们做了什么准备工作：

## 两个ImportSelector

### OAuth2ImportSelector

它是**ImportSelector**的实现类，这是用来配置OAuth2相关的：
```java
final class OAuth2ImportSelector implements ImportSelector {

	@Override
	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		boolean oauth2ClientPresent = ClassUtils.isPresent(
			"org.springframework.security.oauth2.client.registration.ClientRegistration", getClass().getClassLoader());

		return oauth2ClientPresent ?
			new String[] { "org.springframework.security.config.annotation.web.configuration.OAuth2ClientConfiguration" } :
			new String[] {};
	}
}
```
这是一种典型的通过查询某各类是否存在以用来判断某个模块是否存在而进行相应的自动配置的写法，
比如此处实际上是为了查找是否包含了`spring-security-oauth2-client`模块，如果包含则进行相应的自动配置

### SpringWebMvcImportSelector

在`SpringWebMvcImportSelector`中，也采用了同样的机制：
```java
class SpringWebMvcImportSelector implements ImportSelector {

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.context.annotation.ImportSelector#selectImports(org.
	 * springframework .core.type.AnnotationMetadata)
	 */
	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		boolean webmvcPresent = ClassUtils.isPresent(
				"org.springframework.web.servlet.DispatcherServlet",
				getClass().getClassLoader());
		return webmvcPresent
				? new String[] {
						"org.springframework.security.config.annotation.web.configuration.WebMvcSecurityConfiguration" }
				: new String[] {};
	}
}
```
查询是否引入了spring mvc,如果引入，则进行webMvc相关自动配置。
**同时应当留意WebMvcSecurityConfiguration类，很明显，一般情况下我们都会引入spring mvc，也因此，这个自动配置类是一个重要的入口**

----------------

以上，最终剥离了两个主要的自动配置类
* WebMvcSecurityConfiguration:由SpringWebMvcImportSelector类通过查找mvc模块而进行的自动配置类
* WebSecurityConfiguration: 由EnableWebSecurity直接引入的自动配置类
，以及一个不常用的Oauth客户端配置类，可以暂且不管。


### WebMvcSecurityConfiguration

```java
class WebMvcSecurityConfiguration implements WebMvcConfigurer, ApplicationContextAware {
	private BeanResolver beanResolver;

	@Override
	@SuppressWarnings("deprecation")
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
		AuthenticationPrincipalArgumentResolver authenticationPrincipalResolver = new AuthenticationPrincipalArgumentResolver();
		authenticationPrincipalResolver.setBeanResolver(beanResolver);
		argumentResolvers.add(authenticationPrincipalResolver);
		argumentResolvers
				.add(new org.springframework.security.web.bind.support.AuthenticationPrincipalArgumentResolver());

		CurrentSecurityContextArgumentResolver currentSecurityContextArgumentResolver = new CurrentSecurityContextArgumentResolver();
		currentSecurityContextArgumentResolver.setBeanResolver(beanResolver);
		argumentResolvers.add(currentSecurityContextArgumentResolver);
		argumentResolvers.add(new CsrfTokenArgumentResolver());
	}

	@Bean
	public RequestDataValueProcessor requestDataValueProcessor() {
		return new CsrfRequestDataValueProcessor();
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.beanResolver = new BeanFactoryResolver(applicationContext.getAutowireCapableBeanFactory());
	}
}

```

`HandlerMethodArgumentResolver`是spring mvc用来处理controller参数的扩展点，而在此类中插入了两个Resolver,其中`org.springframework.security.web.bind.support.AuthenticationPrincipalArgumentResolver`
是用来兼容以前的注解，可以不关注，直接查看`CurrentSecurityContextArgumentResolver`的代码，其中resolveArgument方法，是主要处理方法，很简单的逻辑：

```java
public final class CurrentSecurityContextArgumentResolver
		implements HandlerMethodArgumentResolver {
//...
    public Object resolveArgument(MethodParameter parameter,
    				ModelAndViewContainer mavContainer, NativeWebRequest webRequest,
    				WebDataBinderFactory binderFactory) throws Exception {
    		SecurityContext securityContext = SecurityContextHolder.getContext();
    		if (securityContext == null) {
    			return null;
    		}
    		Object securityContextResult = securityContext;
    
    		CurrentSecurityContext securityContextAnnotation = findMethodAnnotation(
    				CurrentSecurityContext.class, parameter);
    
    		String expressionToParse = securityContextAnnotation.expression();
    		if (StringUtils.hasLength(expressionToParse)) {
    			StandardEvaluationContext context = new StandardEvaluationContext();
    			context.setRootObject(securityContext);
    			context.setVariable("this", securityContext);
    
    			Expression expression = this.parser.parseExpression(expressionToParse);
    			securityContextResult = expression.getValue(context);
    		}
    
    		if (securityContextResult != null
    				&& !parameter.getParameterType().isAssignableFrom(securityContextResult.getClass())) {
    			if (securityContextAnnotation.errorOnInvalidType()) {
    				throw new ClassCastException(securityContextResult + " is not assignable to "
    						+ parameter.getParameterType());
    			}
    			else {
    				return null;
    			}
    		}
    		return securityContextResult;
    	}
		}
//...
```

主要作用是从`SecurityContextHolder`中获取`SecurityContext`并通过`spel`表达式去转化为我们需要的对象。

简单的理解就是可以用来获取我们当前请求所对应的登录用户


### WebSecurityConfiguration

此配置类就复杂多了，里面涉及到很多构造工厂去帮助我们配置spring security中各种庞杂的过滤器。

需要一点一点梳理

