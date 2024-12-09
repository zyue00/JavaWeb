
<!DOCTYPE html>
<html>
<head>
    <title>课程管理</title>
</head>
<body>
<h1>课程管理</h1>
<h2>创建课程</h2>
<form action="/api/courses" method="post">
    <label for="name">课程名称:</label>
    <input type="text" id="name" name="name" required>
    <br>
    <label for="description">课程描述:</label>
    <textarea id="description" name="description" required></textarea>
    <br>
    <input type="hidden" name="teacherId" value="1"> <!-- 替换为实际教师 ID -->
    <button type="submit">创建课程</button>
</form>
</body>
</html>
