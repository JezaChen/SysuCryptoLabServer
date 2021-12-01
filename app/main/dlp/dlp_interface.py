import time

from flask import request, jsonify
from flask_cors import cross_origin

from app.main import main
from app.main.tools import hex2
from secrets import LAB_COMPUTER_TOKEN

LAST_ECHO_TIME = 0


@main.route('/crypto/pow_mod', methods=["POST"])
@cross_origin()
def calc_pow_mod():
    """
    计算模幂
    返回：text/plain
    :return:
    """
    x = request.form['x']
    y = request.form['y']
    z = request.form['z']

    if x is None or y is None or z is None:
        return jsonify(success=False, reason="参数不全")

    if not x.isdigit() or not y.isdigit() or not z.isdigit():
        return jsonify(success=False, reason="x, y或z至少有一个不是十进制整数")

    try:
        x = int(x)
        y = int(y)
        z = int(z)
        rslt = pow(x, y, z)
        result_dec = str(rslt)
        result_hex = hex2(rslt)
        return jsonify(success=True, result_dec=result_dec, result_hex=result_hex)

    except TypeError:
        return jsonify(success=False, reason="计算过程发生错误，请检查参数是否合法")


@main.route('/crypto/dlp/publish_task', methods=["POST"])
@cross_origin()
def publish_task():
    """
    发布DLP任务
    method: POST
    表单：
    -g: 底数
    返回：json
    - success: 是否成功
    - new_task: 是否是新任务
    - task_id: 任务编号
    - g: 底数
    - finished: 是否完成
    - result: 结果
    :return:
    """
    # FOR DATABASE
    from database.models import Task
    from app_wrapper import db

    g = request.form.get('g')

    if g is None:
        return jsonify(success=False, reason="没有指定g")

    if not g.isdigit():
        return jsonify(success=False, reason="g不是十进制整数")

    task = Task.query.filter(Task.g == g).first()
    if task:
        return jsonify(success=True,
                       new_task=False,
                       task_id=task.id,
                       g=g,
                       finished=task.finished,
                       result=task.result,
                       task_success=task.success)

    new_task = Task(g=g)
    db.session.add(new_task)
    db.session.commit()
    return jsonify(success=True,
                   new_task=True,
                   task_id=new_task.id)


@main.route('/crypto/dlp/get_task', methods=["GET"])
@cross_origin()
def get_task():
    """
    获取DLP任务
    method: GET
    参数：
    -g: 底数
    返回：json
    - success: 是否成功
    - task_id: 任务编号
    - g: 底数
    - finished: 是否完成
    - result: 结果
    :return:
    """
    # FOR DATABASE
    from database.models import Task

    g = request.args.get('g')

    if g is None:
        return jsonify(success=False, reason="没有指定g")

    if not g.isdigit():
        return jsonify(success=False, reason="g不是十进制整数")

    task = Task.query.filter(Task.g == g).first()
    if task:
        return jsonify(success=True,
                       task_id=task.id,
                       g=g,
                       finished=task.finished,
                       result=task.result,
                       task_success=task.success)

    return jsonify(success=False, reason="找不到该任务")


@main.route('/crypto/dlp/pick_task', methods=["GET"])
@cross_origin()
def pick_task():
    """
    获取DLP任务未完成队列中的队头任务
    method: GET
    参数：无
    返回：json
    - task_id: 任务编号
    - g: 底数
    :return:
    """
    token = request.form.get('token')
    if token is None or token != LAB_COMPUTER_TOKEN:
        return jsonify(success=False, reason="token鉴权失败")

    # FOR DATABASE
    from database.models import Task

    global LAST_ECHO_TIME
    LAST_ECHO_TIME = time.time()

    task = Task.query.filter(Task.finished == False).first()
    if task:
        return jsonify(success=True,
                       task_id=task.id,
                       g=task.g)

    return jsonify(success=False, reason="没有未完成的任务")


@main.route('/crypto/dlp/publish_task_result', methods=["POST"])
@cross_origin()
def publish_result():
    """
    公布DLP任务结果
    method: POST
    表单：
    -task_id: 任务id
    -task_success: 任务是否成功
    -result: 任务结果
    -operating_time: DLP计算时间
    返回：json
    - success: 是否成功
    :return:
    """
    token = request.form.get('token')
    if token is None or token != LAB_COMPUTER_TOKEN:
        return jsonify(success=False, reason="token鉴权失败")

    # FOR DATABASE
    from database.models import Task
    from app_wrapper import db

    global LAST_ECHO_TIME
    LAST_ECHO_TIME = time.time()

    task_id = request.form.get('task_id')

    if task_id is None:
        return jsonify(success=False, reason="没有指定task_id")

    if not task_id.isdigit():
        return jsonify(success=False, reason="task_id不是十进制整数")
    task_id = int(task_id)

    task = Task.query.get(task_id)

    if not task:
        return jsonify(success=False,
                       reason="找不到该任务")
    if task.finished:
        return jsonify(success=False,
                       reason="该任务已经结束")

    task_success_str = request.form.get("task_success")
    result = request.form.get("result")
    operating_time_str = request.form.get("operating_time")

    if task_success_str is None or result is None or operating_time_str is None:
        return jsonify(success=False,
                       reason="缺少参数")
    if not operating_time_str.isdigit():
        return jsonify(success=False,
                       reason="参数operating_time需要为十进制整数")

    task_success = (task_success_str == "1")
    operating_time = int(operating_time_str)

    task.finished = True
    task.result = result
    task.success = task_success
    task.operating_time = operating_time

    db.session.commit()
    return jsonify(success=True)


@main.route('/crypto/dlp/current_task_status', methods=["GET"])
@cross_origin()
def current_status():
    """
    获取DLP任务未完成队列中的队头任务
    method: GET
    参数：无
    返回：json
    - task_id: 任务编号
    - g: 底数
    :return:
    """
    # FOR DATABASE
    from database.models import Task

    global LAST_ECHO_TIME

    task_count = Task.query.count()
    not_finished_count = Task.query.filter(Task.finished == False).count()
    current_operating_task = Task.query.filter(Task.finished == False).first()
    current_operating_task_id = 0
    if current_operating_task:
        current_operating_task_id = current_operating_task.id

    return jsonify(success=True,
                   task_count=task_count,
                   not_finished_count=not_finished_count,
                   current_operating_task_id=current_operating_task_id,
                   last_echo_time=LAST_ECHO_TIME)
