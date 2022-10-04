<html>
<head>
    <title>Теория категорий. Нулевое практическое занятие по дисциплине ТСиСА</title>
    <meta charset="utf-8"/>
    <style>
        body {
            font-size: 16px;
            color: #606266;
        }
        ol {
            font-size: 24px;
            color: #606266;
        }
        li {
            padding:5px;
        }
        .task {
            font-size: 24px;
            color: #606266;
        }
        .wo {
            font-size: 24px;
            color: #FF0000;
        }
        td {
            align:center;
            padding: 10px;
            text-align: center;
        }
    </style>
</head>
<body>

<h2 align="center">Информация</h2>


<div class="task">
    Блок можно создать следующим образом:
</div>

<ol>
    <li>
        Для выбора правила отбора отправить GET запрос на http://89.108.115.118/sa/practic0/addsolution с параметром solution<br>
        Пример из области математики или программирования: http://89.108.115.118/sa/practic0/addsolution?solution{"name":"LastName FirstName",
        "group":"group number","objects":"Множество квадратных матриц n-ого порядка",
        "morphisms":"Множество квадратных матриц n-ого порядка таких, что f:A->B, f=A-B, где А и B - объекты",
        "composition":"если f:A->B, g:B->C, то f*g:A->C, f*g=A-C", "id":"нулевая матрица n-ого порядка"}
    </li>
    <li>
        Пример из произвольной области:
        {"name":"LastName FirstName",
        "group":"group number","objects":"Множество населённых пунктов",
        "morphisms":"дороги",
        "composition":"если f:A->B, g:B->C, то f*g:A->C, f*g= дорога из А в С через B", "id":"остаться в исходном населённом пункте"}

</ol>

<div class="wo">
    При отправке данных используйте URLEncode !!!
</div>

<div class="task">
    Пример скрипта на Python:
</div>
<br>
<div>
<code>
    import urllib.request<br>
    import urllib.parse<br>
    data=urllib.parse.quote('{"name":"LastName FirstName", "group":"group number",
    "objects":"", "morphism":"", "composition":"", "id":""}')<br>
    resp = urllib.request.urlopen("http://89.108.115.118/sa/practic0/addsolution?solution=" + data).read()<br>
    print(resp)<br>
</code>
</div>



<table align="center" >
    <tr>
        <td>
            <a href="/sa/">
            <img src="/sa/resources/img/homepage_home_house_icon_225739.svg" width="128"
                 height="128" alt="Главная">
            </a>
        </td>
        <td>
            <a href="/sa/blockchain">
                <img src="/sa/resources/img/archive_document_cloud_data_folder_backup_website_browser_ui_icon_219918.svg"
                     width="128" height="128" alt="Блок-чейн">
            </a>
        </td>
        <td>
            <a href="/sa/task">
                <img src="/sa/resources/img/data_page_sheet_file_type_format_folder_document_ui_icon_219962.svg"
                     width="128" height="128" alt="Задания">
            </a>
        </td>
<!--
        <td><img src="/resources/img/save_document_user_interface_ux_down_download_ui_icon_219961.svg"
                 width="128" height="128" alt="Отправить данные"></td>
-->
    </tr>
    <tr>
        <td>Главная</td><td>Блок-чейн</td>
        <td>Задания</td>
<!--
        <td>Отправить данные</td>
-->
    </tr>
</table>

</body>
</html>

