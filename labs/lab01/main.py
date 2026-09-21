import task1
import task2
import task3

while True:
    num = input("Введіть номер завдання")
    if num not in ['1', '2', '3']:
        break
    if num == '1':
        task1.main()  
    if num == '2':
        task2.main()  
    if num == '3':
        task3.main()

