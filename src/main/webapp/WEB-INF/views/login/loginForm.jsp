<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>로그인양식</title>
<script type="text/javascript" src="../resources/js/common.js"></script>
</head>
<body>

<form id="login" action="/login" method="post">
	아이디 : <input type="text" name="email"/><br/>
	비밀번호 : <input type="password" name="password"/><br/>
	<input type="submit" value="로그인">
</form>
<script>
	<%-- 로그인시 오류 메시지 출력 --%>
	msg = "${error ? exception : ''}";
	if (msg !== "")  {
		alert(msg);
	}
	
	login.addEventListener('submit', function (event) {
		event.preventDefault();
		myFetch("/login", "login", json => {
			if(json.status == 0) {
				//성공
				alert("성공");
				location.href = "/"
			} else {
				alert(json.statusMessage);
			}
		});

	})
			
</script>
</body>
</html>