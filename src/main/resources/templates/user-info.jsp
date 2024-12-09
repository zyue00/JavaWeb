<!DOCTYPE html>
<html>
<head>
    <title>个人信息</title>
</head>
<body>
<h1>个人信息管理</h1>
<div>
    <p>用户名: <span id="username">张三</span></p>
    <p>角色: <span id="role">学生</span></p>
    <p>邮箱: <span id="email">zhangsan@example.com</span></p>
    <p>电话: <span id="phone">1234567890</span></p>
</div>
<form action="/api/users/update" method="post">
    <label for="email">更新邮箱:</label>
    <input type="email" id="email" name="email" required>
    <br>
    <label for="phone">更新电话:</label>
    <input type="text" id="phone" name="phone" required>
    <br>
    <button type="submit">保存修改</button>
</form>
</body>
</html>
