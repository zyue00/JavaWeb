<!DOCTYPE html>
<html>
<head>
    <title>选课系统</title>
</head>
<body>
<h1>学生选课</h1>
<form action="/api/enrollments" method="post">
    <label for="courseId">选择课程:</label>
    <select id="courseId" name="courseId">
        <!-- 替换为动态加载的课程列表 -->
        <option value="101">课程1 - 数学</option>
        <option value="102">课程2 - 物理</option>
    </select>
    <input type="hidden" name="studentId" value="1001"> <!-- 替换为实际学生 ID -->
    <button type="submit">选课</button>
</form>
</body>
</html>
