from flask import Flask
from flask import jsonify, request
import requests
from flask_cors import CORS
from waitress import serve
import datetime
import requests
import re
import json

app = Flask(__name__)
cors = CORS(app)

from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app.config["JWT_SECRET_KEY"]='super-secret' #Cambiar por el que convenga
jwt = JWTManager(app)

@app.route("/login", methods=['POST'])
def create_token():
    data = request.get_json()
    headers = {"Content-Type":"application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + "/usuarios/validar"
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60*60*24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else: 
        return jsonify({"msg": "Bad username or password"}), 401

################# MIDDLEWARE ########################
@app.before_request
def before_request_callback():
    endPoint = limpiarURL(request.path)
    excludeRoutes = ["/login"]
    if excludeRoutes.__contains__(request.path):
        print("ruta excluida", request.path)
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"] is not None:
            tienePermiso = validarPermiso(endPoint, request.method, usuario["rol"]["_id"])
            if not tienePermiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401

def limpiarURL(url):
    partes = request.path.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url

def validarPermiso(endPoint, metodo, idRol):
    url = dataConfig["url-backend-security"]+"/permisos-roles/validar-permiso/rol/"+str(idRol)
    tienePermiso = False
    headers = {"Content-Type":"application/json; charset=utf-8"}
    body = {
        "url": endPoint,
        "metodo": metodo
    }

    response = requests.get(url, json=body, headers=headers)

    try:
        data = response.json()
        if("_id" in data):
            tienePermiso = True
    except:
        pass
    return tienePermiso

###########################################################
################# ENDPOINTS DE MESAS ######################
@app.route("/mesas", methods=['GET'])
def getMesas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/mesas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesas", methods=['POST'])
def crearMesas():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/mesas'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/<string:id>", methods=['GET'])
def getMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/mesas/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/<string:id>", methods=['PUT'])
def modificarMesas(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/mesas/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/mesas/<string:id>", methods=['DELETE'])
def eliminarMesa(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/mesas/'+id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

###########################################################
###              ENDPOINTS DE PARTIDOS                  ###
###########################################################
@app.route("/partidos", methods=['GET'])
def getPartidos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/partidos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/partidos", methods=['POST'])
def crearPartido():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/partidos'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>", methods=['GET'])
def getPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/partidos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>", methods=['PUT'])
def modificarPartido(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/partidos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/partidos/<string:id>", methods=['DELETE'])
def eliminarPartido(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/partidos/'+id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

###########################################################
##              ENDPOINTS DE CANDIDATOS                 ###
###########################################################
@app.route("/candidatos", methods=['GET'])
def getCandidatos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/candidatos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos", methods=['POST'])
def crearCandidato():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/candidatos'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>", methods=['GET'])
def getCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/candidatos/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>", methods=['PUT'])
def modificarCandidato(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/candidatos/'+id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id>", methods=['DELETE'])
def eliminarCandidato(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/candidatos/'+id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/candidatos/<string:id_candidato>/partido/<string:id_partido>", methods=['PUT'])
def asignarPartidoCandidato(id_candidato, id_partido ):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/candidatos/'+id_candidato + "/partido/"+id_partido
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)


#########################################################
####          ENDPOINTS DE RESULTADOS                ####
#########################################################
@app.route("/resultados", methods=['GET'])
def getResultados():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/resultados'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/<string:id>", methods=['GET'])
def getResultado(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/resultados/'+id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/mesa/<string:id_mesa>/candidato/<string:id_candidato>", methods=['POST'])
def crearResultado(id_mesa, id_candidato):
    data = {}
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/resultados/mesa/'+id_mesa+"/candidato/"+id_candidato
    response = requests.post(url, json=data, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/<string:id_resultado>/mesa/<string:id_mesa>/candidato/<string:id_candidato>", methods=['PUT'])
def modificarResultado(id_resultado, id_mesa, id_candidato):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/resultados/'+id_resultado + "/mesa/"+id_mesa+"/candidato/"+id_candidato
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/<string:id>", methods=['DELETE'])
def eliminarResultado(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/resultados/'+id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/mesa/<string:id_mesa>", methods=['GET'])
def inscritosEnMesa(id_mesa):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/resultados/mesa/'+id_mesa
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/candidato_mesas/<string:id_candidato>", methods=['GET'])
def inscritoEnMesas(id_candidato):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/resultados/mesas/'+id_candidato
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

@app.route("/resultados/maxdocument", methods=['GET'])
def getMaxDocument():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-votes"]+'/resultados/maxdocument'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


#########################################################
####          TEST O PRUEBA DE SERVICIO              ####
#########################################################

@app.route("/", methods=['GET'])
def test():
    json = {}
    json["message"]= "Server Running ..."
    return jsonify(json)

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data

if __name__ == "__main__":
    dataConfig = loadFileConfig()
    print("Server running : http://"+dataConfig["url-backend"]+":"+ 
    str(dataConfig["port"]))
    serve(app, host= dataConfig["url-backend"], port=dataConfig["port"]) 