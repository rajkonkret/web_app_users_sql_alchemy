Start-Process -NoNewWindow -FilePath "powershell" -ArgumentList "-ExecutionPolicy Bypass -File C:\Users\Administrator\PycharmProjects\web_app_users_sql_alchemy\start_flask.ps1"

cdm:
cmd /c start /b powershell -ExecutionPolicy Bypass -File C:\Users\Administrator\PycharmProjects\web_app_users_sql_alchemy\start_flask.ps1

nie zamykaj konsoli!!!

Start-Process -FilePath "powershell" -ArgumentList "-ExecutionPolicy Bypass -File C
:\Users\Administrator\PycharmProjects\web_app_users_sql_alchemy\start_flask.ps1" -NoNewWindow -RedirectStandardOutput C:\Users\Administrator\PycharmProjects\web_app_users_sql_alchemy\flask.log -RedirectStandardError C:\Users\Administrator\PycharmProjects\web_app_users_sql_alchemy\flask_error.log

z logami
Start-Process -NoNewWindow -FilePath "powershell" -ArgumentList "-ExecutionPolicy Bypass -File C:\Users\Administrator\PycharmProjects\web_app_users_sql_alchemy\start_flask.ps1" -RedirectStandardOutput C:\Users\Administrator\flask_output.log -RedirectStandardError C:\Users\Administrator\flask_error.log

z logami2
Start-Process -NoNewWindow -FilePath "powershell" -ArgumentList "-ExecutionPolicy Bypass -File C:\Users\Administrator\PycharmProjects\web_app_users_sql_alchemy\start_flask.ps1" -RedirectStandardOutput C:\Users\Administrator\flask_log\flask_output.log -RedirectStandardError C:\Users\Administrator\flask_log\flask_error.log