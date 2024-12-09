<!DOCTYPE html>
<html>
<head>
    <title>用户注册</title>
</head>
<body>
<h1>用户注册</h1>
<form action="/api/users/register" method="post">
    <label for="username">用户名:</label>
    <input type="text" id="username" name="username" required>
    <br>
    <label for="password">密码:</label>
    <input type="password" id="password" name="password" required>
    <br>
    <label for="role">角色:</label>
    <select id="role" name="role">
        <option value="student">学生</option>
        <option value="teacher">教师</option>
        <option value="admin">管理员</option>
    </select>
    <br>
    <label for="email">邮箱:</label>
    <input type="email" id="email" name="email">
    <br>
    <label for="phone">电话:</label>
    <input type="text" id="phone" name="phone">
    <br>
    <button type="submit">注册</button>
</form>
</body>
</html>
