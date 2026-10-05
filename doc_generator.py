import ast
import os
import re

# ============================================================
# НАСТРОЙКИ
# ============================================================
PROJECTS_DIR = "projects"
OUTPUT_FILE = "documentation.txt"
DEBUG = False

IGNORED_DIRS = {
    'venv', '.venv', 'env', '.env',
    '__pycache__', '.git', '.github',
    'node_modules', 'migrations',
    'tests', 'test', 'testing',
    'docs', 'doc', 'examples', 'example',
    '.idea', '.vscode', 'build', 'dist',
    'site-packages', 'lib', 'bin', 'include',
    'static', 'templates',
}

IGNORED_FILES = {
    'setup.py', 'conftest.py', '__init__.py',
    'manage.py', 'wsgi.py', 'asgi.py',
}

KNOWN_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
KNOWN_TYPES = ['string', 'int', 'float', 'path', 'uuid']
KNOWN_ROUTE_DECORATORS = ['route', 'get', 'post', 'put', 'delete', 'patch']
ROUTE_KEYWORDS = ['route', 'url', 'path', 'endpoint', 'api']

# ============================================================
# ХРАНИЛИЩА
# ============================================================
unrecognized = []
suspicious_elements = []
seen_urls = {}
endpoints_confident = []
endpoints_uncertain = []
estimated_missed = []
blueprint_declarations = {}
blueprint_registrations = {}
final_blueprint_prefixes = {}
custom_decorator_cache = {}


def add_warning(file, line, message, context=""):
    unrecognized.append({'file': file, 'line': line,
                         'message': message, 'context': context})


def add_suspicious(file, line, message, context=""):
    suspicious_elements.append({'file': file, 'line': line,
                                'message': message, 'context': context})


def normalize_method(method):
    if isinstance(method, str):
        return method.upper()
    return method


# ============================================================
# ОБХОД ПАПКИ
# ============================================================
def find_python_files(root_dir):
    python_files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for filename in filenames:
            if filename.startswith('test_') or filename.startswith('_test'):
                continue
            if filename.startswith('_'):
                continue
            if filename in IGNORED_FILES:
                continue
            if filename.endswith('.py'):
                python_files.append(os.path.join(dirpath, filename))
    return python_files


def read_file_safe(path):
    try:
        with open(path, encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        try:
            with open(path, encoding='cp1251', errors='replace') as f:
                return f.read()
        except Exception:
            return None
    except Exception:
        return None


# ============================================================
# РАЗРЕШЕНИЕ ЗНАЧЕНИЙ
# ============================================================
def find_file_constants(tree):
    constants = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id
                    if isinstance(node.value, ast.Constant):
                        constants[name] = node.value.value
                    elif isinstance(node.value, ast.List):
                        constants[name] = [
                            elt.value for elt in node.value.elts
                            if isinstance(elt, ast.Constant)
                        ]
                    elif isinstance(node.value, ast.Tuple):
                        constants[name] = [
                            elt.value for elt in node.value.elts
                            if isinstance(elt, ast.Constant)
                        ]
                    elif isinstance(node.value, ast.Dict):
                        d = {}
                        for k, v in zip(node.value.keys, node.value.values):
                            if isinstance(k, ast.Constant) and isinstance(v, ast.Constant):
                                d[k.value] = v.value
                        constants[name] = d
    return constants


def resolve_value(node, constants, depth=0):
    if depth > 15:
        return '<too-deep>'
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in constants:
            return constants[node.id]
        return f'<{node.id}>'
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = resolve_value(node.left, constants, depth + 1)
        right = resolve_value(node.right, constants, depth + 1)
        return f'{left}{right}'
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            elif isinstance(v, ast.FormattedValue):
                parts.append(str(resolve_value(v.value, constants, depth + 1)))
        return ''.join(parts)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'format':
            base_template = resolve_value(node.func.value, constants, depth + 1)
            if not isinstance(base_template, str):
                return '<format>'
            format_args = [str(resolve_value(a, constants, depth + 1))
                           for a in node.args]
            format_kwargs = {
                kw.arg: str(resolve_value(kw.value, constants, depth + 1))
                for kw in node.keywords if kw.arg
            }
            try:
                if format_kwargs:
                    return base_template.format(**format_kwargs)
                return base_template.format(*format_args)
            except (IndexError, KeyError, ValueError):
                return f'{base_template}<format>'
        if isinstance(node.func, ast.Name):
            return f'<call:{node.func.id}>'
        if isinstance(node.func, ast.Attribute):
            return f'<call:{node.func.attr}>'
        return '<call>'
    if isinstance(node, ast.Subscript):
        obj = resolve_value(node.value, constants, depth + 1)
        if isinstance(obj, dict):
            key_node = node.slice
            if isinstance(key_node, ast.Constant):
                key = key_node.value
                if key in obj:
                    return obj[key]
        return '<subscript>'
    return '<unknown>'


# ============================================================
# АНАЛИЗ САМОДЕЛЬНЫХ ДЕКОРАТОРОВ
# ============================================================
def analyze_custom_decorator(decorator_name, all_files):
    if decorator_name in custom_decorator_cache:
        return custom_decorator_cache[decorator_name]

    for filepath in all_files:
        content = read_file_safe(filepath)
        if content is None:
            continue
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == decorator_name:
                    result = _analyze_decorator_body(node)
                    custom_decorator_cache[decorator_name] = result
                    return result

    custom_decorator_cache[decorator_name] = 'unknown'
    return 'unknown'


def _analyze_decorator_body(func_node):
    for stmt in ast.walk(func_node):
        if isinstance(stmt, ast.Call):
            if isinstance(stmt.func, ast.Attribute):
                if stmt.func.attr == 'add_url_rule':
                    return 'route'
                if stmt.func.attr in ['route', 'get', 'post', 'put', 'delete', 'patch']:
                    return 'route'
            if isinstance(stmt.func, ast.Name):
                if any(w in stmt.func.id.lower() for w in ROUTE_KEYWORDS):
                    return 'route'

    for stmt in ast.walk(func_node):
        if isinstance(stmt, ast.Attribute):
            if stmt.attr in ['route', 'add_url_rule']:
                return 'route'

    for stmt in ast.walk(func_node):
        if isinstance(stmt, ast.Call):
            if isinstance(stmt.func, ast.Attribute):
                if stmt.func.attr in ['login_required', 'cache', 'wraps',
                                       'lru_cache', 'before_request']:
                    return 'not_route'
    return 'not_route'


def find_custom_decorators(tree, filepath, all_files):
    standard = set(KNOWN_ROUTE_DECORATORS) | {
        'login_required', 'marshal_with', 'expect', 'doc',
        'staticmethod', 'classmethod', 'property'
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                name = None
                if isinstance(dec, ast.Call):
                    if isinstance(dec.func, ast.Attribute):
                        name = dec.func.attr
                    elif isinstance(dec.func, ast.Name):
                        name = dec.func.id
                elif isinstance(dec, ast.Attribute):
                    name = dec.attr
                elif isinstance(dec, ast.Name):
                    name = dec.id

                if name and name not in standard:
                    if any(w in name.lower() for w in ROUTE_KEYWORDS):
                        dec_type = analyze_custom_decorator(name, all_files)
                        if dec_type == 'route':
                            add_suspicious(
                                filepath, node.lineno,
                                f"Самодельный декоратор @{name} — распознан как эндпоинт",
                                f"функция {node.name}"
                            )
                        elif dec_type == 'not_route':
                            if DEBUG:
                                print(f"  [SKIP] @{name} — не эндпоинт")
                        else:
                            add_suspicious(
                                filepath, node.lineno,
                                f"Подозрительный декоратор @{name}",
                                f"функция {node.name}"
                            )


def is_custom_route_decorator(decorator_name, all_files):
    return analyze_custom_decorator(decorator_name, all_files) == 'route'


# ============================================================
# ИЗВЛЕЧЕНИЕ ИНФОРМАЦИИ ИЗ ДЕКОРАТОРА
# ============================================================
def extract_decorator_info(dec, constants):
    info = {'object': None, 'name': None, 'args': [], 'kwargs': {},
            'lineno': getattr(dec, 'lineno', 0),
            'has_starargs': False, 'has_starkwargs': False}

    if isinstance(dec, ast.Call):
        if isinstance(dec.func, ast.Attribute):
            info['object'] = dec.func.value.id if hasattr(dec.func.value, 'id') else None
            info['name'] = dec.func.attr
        elif isinstance(dec.func, ast.Name):
            info['name'] = dec.func.id

        for arg in dec.args:
            if isinstance(arg, ast.Starred):
                info['has_starargs'] = True
                info['args'].append('<*args>')
            else:
                info['args'].append(resolve_value(arg, constants))

        for kw in dec.keywords:
            if kw.arg is None:
                info['has_starkwargs'] = True
                continue
            if kw.arg == 'methods':
                resolved = resolve_methods(kw.value, constants)
                if resolved:
                    info['kwargs']['methods'] = resolved
            else:
                info['kwargs'][kw.arg] = resolve_value(kw.value, constants)

    elif isinstance(dec, ast.Attribute):
        info['object'] = dec.value.id if hasattr(dec.value, 'id') else None
        info['name'] = dec.attr
    elif isinstance(dec, ast.Name):
        info['name'] = dec.id
    return info


def resolve_methods(node, constants):
    if isinstance(node, ast.Constant) and node.value is None:
        return ['GET']
    value = resolve_value(node, constants)
    if isinstance(value, list):
        methods = [normalize_method(m) for m in value if isinstance(m, str)]
        return methods if methods else ['GET']
    if isinstance(value, tuple):
        methods = [normalize_method(m) for m in value if isinstance(m, str)]
        return methods if methods else ['GET']
    if isinstance(value, str):
        if value.startswith('<') and value.endswith('>'):
            return ['GET']
        return [normalize_method(value)]
    return ['GET']


# ============================================================
# BLUEPRINT
# ============================================================
def extract_url_prefix_from_call(call_node, constants):
    for kw in call_node.keywords:
        if kw.arg == 'url_prefix':
            val = resolve_value(kw.value, constants)
            if isinstance(val, str):
                return val
            return None
    return None


def collect_blueprints_phase1(all_files):
    global blueprint_declarations, blueprint_registrations
    for filepath in all_files:
        content = read_file_safe(filepath)
        if content is None:
            continue
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue
        constants = find_file_constants(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Name):
                        if node.value.func.id == 'Blueprint':
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    var_name = target.id
                                    prefix = extract_url_prefix_from_call(node.value, constants)
                                    if var_name not in blueprint_declarations:
                                        blueprint_declarations[var_name] = {
                                            'file': filepath, 'prefix': prefix,
                                            'line': node.lineno
                                        }
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'register_blueprint':
                        if node.args and isinstance(node.args[0], ast.Name):
                            var_name = node.args[0].id
                            prefix = extract_url_prefix_from_call(node, constants)
                            if var_name not in blueprint_registrations:
                                blueprint_registrations[var_name] = {
                                    'file': filepath, 'prefix': prefix,
                                    'line': node.lineno
                                }


def merge_blueprint_prefixes():
    global final_blueprint_prefixes
    final_blueprint_prefixes = {}
    all_vars = set(blueprint_declarations.keys()) | set(blueprint_registrations.keys())
    for var_name in all_vars:
        decl = blueprint_declarations.get(var_name, {}).get('prefix') or ''
        reg = blueprint_registrations.get(var_name, {}).get('prefix') or ''
        if decl and not decl.startswith('/'):
            decl = '/' + decl
        if reg and not reg.startswith('/'):
            reg = '/' + reg
        final_blueprint_prefixes[var_name] = decl + reg


# ============================================================
# ОЦЕНКА ПРОПУЩЕННЫХ (K)
# ============================================================
def estimate_missed_endpoints(tree, filepath):
    estimated = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.While)):
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Attribute):
                        if child.func.attr == 'add_url_rule':
                            estimated.append({
                                'file': filepath, 'line': child.lineno,
                                'reason': 'add_url_rule в цикле', 'estimate': 3
                            })
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr == 'add_url_rule':
                    in_loop = False
                    for parent in ast.walk(tree):
                        if isinstance(parent, (ast.For, ast.While)):
                            for sub in ast.walk(parent):
                                if sub is node:
                                    in_loop = True
                    if not in_loop:
                        estimated.append({
                            'file': filepath, 'line': node.lineno,
                            'reason': 'add_url_rule вне цикла', 'estimate': 1
                        })
    return estimated


# ============================================================
# ВАЛИДАЦИЯ
# ============================================================
def validate_url_and_methods(url, methods, dec_lineno, node_name, node_type, filepath):
    if url == '':
        add_warning(filepath, dec_lineno, "Пустой URL", f"{node_type} {node_name}")
    elif url and not url.startswith('/') and not url.startswith('<'):
        add_warning(filepath, dec_lineno,
                    f"URL '{url}' должен начинаться с '/'", f"{node_type} {node_name}")
    if url and url in seen_urls:
        add_warning(filepath, dec_lineno,
                    f"URL '{url}' уже определён в {seen_urls[url]}", f"{node_type} {node_name}")
    elif url:
        seen_urls[url] = filepath
    for method in methods:
        if isinstance(method, str) and not method.startswith('<'):
            if method.upper() not in KNOWN_METHODS:
                add_warning(filepath, dec_lineno,
                            f"Неизвестный HTTP-метод: {method}",
                            f"{node_type} {node_name}, URL: {url}")


def validate_path_params(url, node_lineno, node_name, node_type, filepath):
    path_params = []
    if not url:
        return path_params
    matches = re.findall(r'<([^>]+)>', url)
    for match in matches:
        if ':' not in match and len(match) < 20 and match.isupper():
            continue
        if match.startswith('var:'):
            continue
        if ':' in match:
            param_type, param_name = match.split(':', 1)
            if param_type not in KNOWN_TYPES:
                add_warning(filepath, node_lineno,
                            f"Неизвестный тип '{param_type}'",
                            f"{node_type} {node_name}, URL: {url}")
            path_params.append({'name': param_name, 'type': param_type})
        else:
            path_params.append({'name': match, 'type': 'string'})
            add_warning(filepath, node_lineno,
                        f"Параметр пути '{match}' без типа",
                        f"{node_type} {node_name}, URL: {url}")
    return path_params


def find_query_params(node):
    params = []
    seen = set()
    for stmt in ast.walk(node):
        if isinstance(stmt, ast.Call):
            if isinstance(stmt.func, ast.Attribute) and stmt.func.attr == 'get':
                if isinstance(stmt.func.value, ast.Attribute):
                    if stmt.func.value.attr in ('args', 'values', 'form'):
                        if stmt.args and isinstance(stmt.args[0], ast.Constant):
                            name = stmt.args[0].value
                            if name not in seen:
                                seen.add(name)
                                params.append({'name': name,
                                               'source': 'request.' + stmt.func.value.attr + '.get'})
        if isinstance(stmt, ast.Subscript):
            if isinstance(stmt.value, ast.Attribute):
                if stmt.value.attr in ('args', 'values', 'form'):
                    if isinstance(stmt.slice, ast.Constant):
                        name = stmt.slice.value
                        if name not in seen:
                            seen.add(name)
                            params.append({'name': name,
                                           'source': 'request.' + stmt.value.attr + '[...]'})
    return params


def find_add_url_rule(tree, filepath):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'add_url_rule':
                url = None
                if node.args and isinstance(node.args[0], ast.Constant):
                    url = node.args[0].value
                elif node.args:
                    url = '<expression>'
                in_loop = False
                for parent in ast.walk(tree):
                    if isinstance(parent, (ast.For, ast.While)):
                        for child in ast.walk(parent):
                            if child is node:
                                in_loop = True
                add_suspicious(filepath, node.lineno,
                               f"add_url_rule{' в цикле' if in_loop else ''}",
                               f"URL: {url}")


# ============================================================
# АНАЛИЗ ОДНОГО ФАЙЛА
# ============================================================
def analyze_file(filepath, output, all_files):
    content = read_file_safe(filepath)
    if content is None:
        return

    try:
        tree = ast.parse(content)
    except SyntaxError as e:
        output.append(f"⚠️  НЕ РАЗОБРАН: {filepath}")
        output.append(f"     Синтаксическая ошибка строка {e.lineno}: {e.msg}")
        output.append("")
        add_warning(filepath, e.lineno or 0, f"Синтаксическая ошибка: {e.msg}", "")
        return

    constants = find_file_constants(tree)
    find_add_url_rule(tree, filepath)
    find_custom_decorators(tree, filepath, all_files)

    estimated = estimate_missed_endpoints(tree, filepath)
    estimated_missed.extend(estimated)

    rel_path = filepath

    # ======== ФУНКЦИИ С @route (включая самодельные) ========
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            all_decorators = []
            route_decorator = None
            url = None
            methods = ['GET']
            has_starargs = False
            has_starkwargs = False
            is_custom = False

            for dec in node.decorator_list:
                dec_info = extract_decorator_info(dec, constants)
                all_decorators.append(dec_info)

                if dec_info.get('has_starargs'):
                    has_starargs = True
                if dec_info.get('has_starkwargs'):
                    has_starkwargs = True

                dec_name = dec_info.get('name')

                is_standard_route = dec_name in KNOWN_ROUTE_DECORATORS
                is_custom_route = (
                    dec_name and
                    dec_name not in KNOWN_ROUTE_DECORATORS and
                    any(w in dec_name.lower() for w in ROUTE_KEYWORDS) and
                    is_custom_route_decorator(dec_name, all_files)
                )

                if is_standard_route or is_custom_route:
                    route_decorator = dec_info
                    if is_custom_route:
                        is_custom = True

                    if dec_info.get('args'):
                        url = dec_info['args'][0]
                    else:
                        add_warning(filepath,
                                    f"{dec_info.get('lineno', node.lineno)}, {node.lineno}",
                                    f"Не удалось извлечь URL из @{dec_name}",
                                    f"функция {node.name}")
                        continue
                    if dec_name in ['get', 'post', 'put', 'delete', 'patch']:
                        methods = [dec_name.upper()]
                    if 'methods' in dec_info.get('kwargs', {}):
                        methods = dec_info['kwargs']['methods']

            if route_decorator and url is not None:
                url = str(url)
                bp_var = route_decorator.get('object')

                if bp_var and bp_var in final_blueprint_prefixes:
                    prefix = final_blueprint_prefixes[bp_var]
                    if prefix:
                        if url == '/':
                            url = prefix + '/'
                        elif not url.startswith(prefix):
                            url = prefix + url

                is_uncertain = ('<' in url and '>' in url) or \
                               any(isinstance(m, str) and m.startswith('<') for m in methods) or \
                               has_starargs or has_starkwargs or is_custom

                record = {
                    'url': url, 'file': rel_path, 'line': node.lineno,
                    'methods': methods, 'name': node.name, 'type': 'function',
                    'blueprint': bp_var, 'custom_decorator': is_custom
                }

                if is_uncertain:
                    endpoints_uncertain.append(record)
                else:
                    endpoints_confident.append(record)

                validate_url_and_methods(url, methods,
                                         route_decorator.get('lineno', node.lineno),
                                         node.name, "функция", filepath)
                path_params = validate_path_params(url, node.lineno, node.name,
                                                    "функция", filepath)
                query_params = find_query_params(node)

                if any(m in methods for m in ['POST', 'PUT', 'PATCH']):
                    has_body = False
                    for stmt in ast.walk(node):
                        if isinstance(stmt, ast.Assign):
                            if isinstance(stmt.value, ast.Call):
                                if (isinstance(stmt.value.func, ast.Attribute) and
                                    isinstance(stmt.value.func.value, ast.Name) and
                                    stmt.value.func.value.id == 'request' and
                                    stmt.value.func.attr in ['get_json', 'json']):
                                    has_body = True
                                if (isinstance(stmt.value.func, ast.Attribute) and
                                    stmt.value.func.attr == 'loads'):
                                    has_body = True
                    if not has_body:
                        name_lower = node.name.lower()
                        if not any(w in name_lower for w in ['logout', 'login', 'auth']):
                            add_warning(filepath, node.lineno,
                                        f"Метод {'/'.join(m for m in methods if m in ['POST','PUT','PATCH'])} "
                                        f"ожидает тело, но request.get_json()/json.loads не найден",
                                        f"функция {node.name}, URL: {url}")

                if '<' in url and '>' in url:
                    add_warning(filepath, node.lineno,
                                f"URL содержит нераскрытые переменные: {url}",
                                f"функция {node.name}")

                mark = "❓" if is_uncertain else "📍"
                output.append(f"{mark} ЭНДПОИНТ: {url}")
                output.append(f"   📌 Файл: {rel_path}")
                output.append(f"   📌 Функция: {node.name}")
                output.append(f"   📌 Строка: {node.lineno}")
                output.append(f"   📌 Методы: {', '.join(methods)}")
                if is_custom:
                    output.append(f"   📌 Декоратор: @{route_decorator.get('name')} (самодельный, распознан)")
                if bp_var and bp_var in final_blueprint_prefixes:
                    output.append(f"   📌 Blueprint: {bp_var} (итоговый prefix={final_blueprint_prefixes[bp_var] or '(нет)'})")

                for dec_info in all_decorators:
                    if dec_info.get('name') not in KNOWN_ROUTE_DECORATORS:
                        if dec_info.get('name') != route_decorator.get('name'):
                            dec_str = ""
                            if dec_info.get('object'):
                                dec_str += f"{dec_info['object']}."
                            dec_str += dec_info.get('name') or ''
                            output.append(f"   📌 Декоратор: @{dec_str}")

                if path_params:
                    output.append(f"   📌 Параметры пути:")
                    for p in path_params:
                        output.append(f"      - {p['name']} ({p['type']})")

                if query_params:
                    output.append(f"   📌 Параметры запроса:")
                    for p in query_params:
                        output.append(f"      - {p['name']} ({p['source']})")

                output.append(f"   📌 Пример запроса:")
                for method in methods:
                    if not isinstance(method, str):
                        method = str(method)
                    if method.startswith('<'):
                        output.append(f"      GET {url}   (метод не раскрыт — предполагается GET)")
                    elif method == 'GET':
                        output.append(f"      GET {url}")
                    elif method in ['POST', 'PUT', 'PATCH']:
                        output.append(f"      {method} {url}")
                        output.append(f"      Content-Type: application/json")
                    elif method == 'DELETE':
                        output.append(f"      {method} {url}")
                output.append("")

    # ======== КЛАССЫ С @route ========
    for class_node in ast.walk(tree):
        if isinstance(class_node, ast.ClassDef):
            class_decorators = []
            route_decorator = None
            url = None
            methods = ['GET']

            for dec in class_node.decorator_list:
                dec_info = extract_decorator_info(dec, constants)
                class_decorators.append(dec_info)

                dec_name = dec_info.get('name')
                is_standard_route = dec_name in KNOWN_ROUTE_DECORATORS
                is_custom_route = (
                    dec_name and
                    dec_name not in KNOWN_ROUTE_DECORATORS and
                    any(w in dec_name.lower() for w in ROUTE_KEYWORDS) and
                    is_custom_route_decorator(dec_name, all_files)
                )

                if is_standard_route or is_custom_route:
                    route_decorator = dec_info
                    if dec_info.get('args'):
                        url = dec_info['args'][0]
                    else:
                        add_warning(filepath,
                                    f"{dec_info.get('lineno', class_node.lineno)}, {class_node.lineno}",
                                    "Не удалось извлечь URL из @route",
                                    f"класс {class_node.name}")
                        continue
                    if 'methods' in dec_info.get('kwargs', {}):
                        methods = dec_info['kwargs']['methods']

            if route_decorator and url is not None:
                url = str(url)
                bp_var = route_decorator.get('object')

                if bp_var and bp_var in final_blueprint_prefixes:
                    prefix = final_blueprint_prefixes[bp_var]
                    if prefix:
                        if url == '/':
                            url = prefix + '/'
                        elif not url.startswith(prefix):
                            url = prefix + url

                http_methods = []
                for item in class_node.body:
                    if isinstance(item, ast.FunctionDef):
                        if item.name in ['get', 'post', 'put', 'delete', 'patch']:
                            http_methods.append(item.name.upper())

                if not http_methods:
                    add_warning(filepath, class_node.lineno,
                                "В классе с @route нет HTTP-методов",
                                f"класс {class_node.name}")

                is_uncertain = ('<' in url and '>' in url)
                record = {
                    'url': url, 'file': rel_path, 'line': class_node.lineno,
                    'methods': methods, 'name': class_node.name, 'type': 'class',
                    'blueprint': bp_var
                }
                if is_uncertain:
                    endpoints_uncertain.append(record)
                else:
                    endpoints_confident.append(record)

                mark = "❓" if is_uncertain else "📍"
                output.append(f"{mark} ЭНДПОИНТ: {url}")
                output.append(f"   📌 Файл: {rel_path}")
                output.append(f"   📌 Класс: {class_node.name}")
                output.append(f"   📌 Строка: {class_node.lineno}")
                output.append(f"   📌 Методы: {', '.join(methods)}")
                if http_methods:
                    output.append(f"   📌 HTTP методы в классе: {', '.join(http_methods)}")
                if bp_var and bp_var in final_blueprint_prefixes:
                    output.append(f"   📌 Blueprint: {bp_var} (итоговый prefix={final_blueprint_prefixes[bp_var] or '(нет)'})")
                output.append("")

    # ======== Flask-RESTful Resource ========
    for class_node in ast.walk(tree):
        if isinstance(class_node, ast.ClassDef):
            is_resource = False
            for base in class_node.bases:
                if isinstance(base, ast.Name) and base.id == 'Resource':
                    is_resource = True
                elif isinstance(base, ast.Attribute) and base.attr == 'Resource':
                    is_resource = True
            if not is_resource:
                continue
            has_route = False
            for dec in class_node.decorator_list:
                dec_info = extract_decorator_info(dec, constants)
                if dec_info.get('name') in KNOWN_ROUTE_DECORATORS:
                    has_route = True
            if has_route:
                continue

            http_methods = []
            for item in class_node.body:
                if isinstance(item, ast.FunctionDef):
                    if item.name in ['get', 'post', 'put', 'delete', 'patch']:
                        http_methods.append(item.name.upper())

            if http_methods:
                endpoints_uncertain.append({
                    'url': '<via add_resource>', 'file': rel_path,
                    'line': class_node.lineno, 'methods': http_methods,
                    'name': class_node.name, 'type': 'resource',
                    'blueprint': None
                })
                output.append(f"❓ ЭНДПОИНТ: (URL через api.add_resource)")
                output.append(f"   📌 Файл: {rel_path}")
                output.append(f"   📌 Класс: {class_node.name}")
                output.append(f"   📌 Строка: {class_node.lineno}")
                output.append(f"   📌 HTTP методы: {', '.join(http_methods)}")
                output.append("")
                add_warning(filepath, class_node.lineno,
                            "Класс Resource без URL",
                            f"класс {class_node.name}")


# ============================================================
# МЕТРИКА ПОКРЫТИЯ (N / M / K)
# ============================================================
def format_coverage_metrics():
    N = len(endpoints_confident)
    M = len(endpoints_uncertain)
    K = sum(e['estimate'] for e in estimated_missed)
    total = N + M + K
    if total == 0:
        return ["Метрика: эндпоинты не найдены."]

    lines = []
    lines.append(f"Распознано уверенно (N):        {N}  ({round(N / total * 100, 1)}%)")
    lines.append(f"Помечено как неуверенные (M):   {M}  ({round(M / total * 100, 1)}%)")
    lines.append(f"Оценочно пропущено (K):         {K}  ({round(K / total * 100, 1)}%)")
    lines.append(f"{'─' * 50}")
    lines.append(f"Итого оценочно:                 {total} (100%)")
    accuracy = round(N / total * 100, 1)
    lines.append(f"Точность парсера (N / total):   {accuracy}%")
    return lines


# ============================================================
# ВВОД ОЖИДАЕМОГО КОЛИЧЕСТВА
# ============================================================
def ask_expected_count():
    print()
    print("=" * 70)
    print("📊 ПОДСЧЁТ ТОЧНОСТИ ПАРСЕРА")
    print("=" * 70)
    print("Сколько эндпоинтов ДОЛЖНО быть в проекте?")
    print("(если не знаете — введите 0)")
    print()
    try:
        answer = input("Ожидаемое количество: ").strip()
        return int(answer) if answer else 0
    except (ValueError, EOFError, KeyboardInterrupt):
        return 0

# ============================================================
# ГЛАВНАЯ ФУНКЦИЯ
# ============================================================
def main():
    if not os.path.exists(PROJECTS_DIR):
        print(f"❌ Папка '{PROJECTS_DIR}' не найдена!")
        return

    expected_count = ask_expected_count()

    print()
    print(f"🔍 Поиск .py файлов в папке: {PROJECTS_DIR}")
    python_files = find_python_files(PROJECTS_DIR)
    print(f"✅ Найдено файлов: {len(python_files)}")

    if not python_files:
        print("❌ Не найдено ни одного .py файла.")
        return

    # ============ ЭТАП 1: Сбор Blueprint ============
    print()
    print("=" * 70)
    print("📡 ЭТАП 1: Межфайловый анализ Blueprint")
    print("=" * 70)
    collect_blueprints_phase1(python_files)
    merge_blueprint_prefixes()

    print(f"Найдено Blueprint-объявлений: {len(blueprint_declarations)}")
    print(f"Найдено Blueprint-регистраций: {len(blueprint_registrations)}")
    print()
    if final_blueprint_prefixes:
        print("Итоговые префиксы Blueprint:")
        for var, prefix in sorted(final_blueprint_prefixes.items()):
            src_decl = blueprint_declarations.get(var, {}).get('file', '—')
            src_reg = blueprint_registrations.get(var, {}).get('file', '—')
            print(f"  {var:20s} → {prefix or '(нет)':20s} "
                  f"(объявлен: {os.path.basename(src_decl)}, "
                  f"зарегистрирован: {os.path.basename(src_reg)})")
    print()

    # ============ ЭТАП 2: Анализ эндпоинтов ============
    print("=" * 70)
    print("📄 ЭТАП 2: Анализ эндпоинтов")
    print("=" * 70)
    output = []
    for i, filepath in enumerate(python_files, 1):
        print(f"[{i}/{len(python_files)}] {filepath}")
        analyze_file(filepath, output, python_files)

    found_total = len(endpoints_confident) + len(endpoints_uncertain)

    print()
    print("=" * 70)
    print("📊 МЕТРИКА ПОКРЫТИЯ")
    print("=" * 70)
    for line in format_coverage_metrics():
        print(line)
    print()
    print(f"Ожидалось (по вводу):  {expected_count}")
    print(f"Найдено всего:         {found_total}")
    print("=" * 70)

    # ============ СБОРКА ФИНАЛЬНОГО ФАЙЛА ============
    full = []
    full.append("=" * 70)
    full.append("📄 ДОКУМЕНТАЦИЯ API")
    full.append("=" * 70)
    full.append("")
    full.extend(output)

    # Метрика покрытия
    full.append("")
    full.append("=" * 70)
    full.append("📊 МЕТРИКА ПОКРЫТИЯ")
    full.append("=" * 70)
    full.extend(format_coverage_metrics())
    full.append("")
    if expected_count > 0:
        percent = round(found_total / expected_count * 100, 1) if expected_count else 0
        full.append(f"Заявленное ожидаемое: {expected_count}")
        full.append(f"Фактически найдено:   {found_total} ({percent}%)")
    full.append("")

    # Подозрительные места (M)
    if suspicious_elements:
        full.append("=" * 70)
        full.append("🟡 ПОДОЗРИТЕЛЬНЫЕ МЕСТА (M — неуверенные)")
        full.append("=" * 70)
        for i, s in enumerate(suspicious_elements, 1):
            full.append(f"[{i}] 📄 Файл: {s['file']}")
            full.append(f"    📄 Строка: {s['line']}")
            full.append(f"    ❓ {s['message']}")
            if s['context']:
                full.append(f"    📎 Контекст: {s['context']}")
            full.append("")
        full.append("=" * 70)
        full.append("👆 Проверьте эти места вручную")
        full.append("=" * 70)
        full.append("")

    # Оценочно пропущенные (K)
    if estimated_missed:
        full.append("=" * 70)
        full.append("🔴 ОЦЕНОЧНО ПРОПУЩЕННЫЕ (K)")
        full.append("=" * 70)
        for i, m in enumerate(estimated_missed, 1):
            full.append(f"[{i}] 📄 Файл: {m['file']}")
            full.append(f"    📄 Строка: {m['line']}")
            full.append(f"    ❗ {m['reason']}")
            full.append(f"    📊 Оценочно эндпоинтов: ~{m['estimate']}")
            full.append("")
        full.append("=" * 70)
        full.append("👆 Эти эндпоинты парсер не смог распознать автоматически")
        full.append("=" * 70)
        full.append("")

    # Фильтр нераспознанных
    full.append("=" * 70)
    full.append("⚠️  ФИЛЬТР НЕРАСПОЗНАННЫХ ЭЛЕМЕНТОВ")
    full.append("=" * 70)
    if not unrecognized:
        full.append("✅ Все эндпоинты распознаны успешно!")
    else:
        full.append(f"Найдено проблем: {len(unrecognized)}\n")
        for i, warn in enumerate(unrecognized, 1):
            full.append(f"[{i}] 📄 Файл: {warn['file']}")
            full.append(f"    📄 Строка: {warn['line']}")
            full.append(f"    ❗ {warn['message']}")
            if warn['context']:
                full.append(f"    📎 Контекст: {warn['context']}")
            full.append("")
    full.append("=" * 70)
    full.append("👆 Проверьте эти места в исходных файлах вручную")
    full.append("=" * 70)

    # Запись в файл
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(full))

    print(f"💾 Результат сохранён в файл: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()