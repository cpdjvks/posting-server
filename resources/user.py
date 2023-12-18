from flask import request
from flask_jwt_extended import create_access_token, get_jwt, jwt_required
from flask_restful import Resource
from mysql_connection import get_connection
from mysql.connector import Error

from email_validator import validate_email, EmailNotValidError

from utils import check_password, hash_password


class UserRegisterResource(Resource) :

    def post(self) :

        data = request.get_json()

        # 이메일 주소형식이 올바른지 확인한다.
        try : 
            validate_email(data['email'])
        except EmailNotValidError as e :
            print(e)
            return {'error' : str(e)}, 400
        
        # 비밀번호 길이가 유효한지 체크한다.
        if len( data['password']) < 4 or len( data['password']) > 14:
            return {'error' : '비번 길이가 올바르지 않습니다.'} , 400

        # 비밀번호를 암호화 한다.
        password = hash_password(data['password']) 

        # DB의 user 테이블에 저장 
        try : 
            connection = get_connection()
            query = '''insert into user 
                    (email, password)
                    values
                    (%s, %s);'''
            record = (data['email'],
                        password)
            
            cursor = connection.cursor()
            cursor.execute(query, record)
            connection.commit()

            # 테이블에 방금 insert 한 데이터의 아이디를 가져오는 방법 
            user_id = cursor.lastrowid

            cursor.close()
            connection.close()

        except Error as e :
            print(e)
            cursor.close()
            connection.close()
            return {'error' : str(e)} , 500

        # user 테이블의 id 로 JWT 토큰을 만들어야 한다. 
        access_token = create_access_token(user_id)        

        # 토큰을 클라이언트에게 준다. response
        return {'result' : 'success' , 
                'access_token' : access_token}, 200


class UserLoginResource(Resource) :

    def post(self) :

        data = request.get_json()

        try :
            connection = get_connection()
            query = '''select *
                        from user
                        where email = %s ;'''
            record = (data['email'] ,  )

            cursor = connection.cursor(dictionary=True)
            cursor.execute(query, record)

            result_list = cursor.fetchall()

            print(result_list)

            cursor.close()
            connection.close()

        except Error as e:
            print(e)
            cursor.close()
            connection.close()
            return {"error" : str(e)}, 500
        
        if len(result_list) == 0 :
            return {"error" : "회원가입을 하세요."}, 400

        check = check_password(data['password'], result_list[0]['password'])

        if check == False :
            return {"error" : "비번이 맞지않습니다."}, 406

        access_token = create_access_token(result_list[0]['id'])

        return {"result" : "success",
                "access_token" : access_token}, 200


jwt_blocklist = set()

class UserLogoutResource(Resource) :

    @jwt_required()
    def delete(self) :

        jti = get_jwt()['jti']
        print(jti)

        jwt_blocklist.add(jti)

        return {"result" : "success"}, 200






