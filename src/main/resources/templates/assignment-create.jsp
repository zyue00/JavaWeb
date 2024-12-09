<!DOCTYPE html>
<html>
<head>
    <title>发布作业</title>
</head>
<body>
<h1>发布作业</h1>
<form action="/api/assignments" method="post">
    <label for="courseId">所属课程:</label>
    <select id="courseId" name="courseId">
        <!-- 替换为动态加载的课程列表 -->
        <option value="101">课程1 - 数学</option>
        <option value="102">课程2 - 物理</option>
    </select>
    <br>
    <label for="title">作业标题:</label>
    <input type="text" id="title" name="title" required>
    <br>
    <label for="description">作业描述:</label>
    <textarea id="description" name="description" required></textarea>
    <br>
    <label for="deadline">截止日期:</label>
    <input type="datetime-local" id="deadline" name="deadline" required>
    <br>
    <button type="submit">发布作业</button>
</form>
</body>
</html>
