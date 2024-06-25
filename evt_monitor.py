
import os
import time


def hex_2_int(hex_str):
    """
    16进制字符串转10进制数字
    :param hex_str: 字符串
    :return: 
    """
    return int(hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2], 16)


def hex_2_hex(hex_str):
    """
    16进制字符串调整顺序
    :param hex_str: 
    :return: 
    """
    return hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]


def timestamp_2_datetime(timestamp):
    """
    将时间戳转换成日期+时间格式
    evt中记录的时间是UTC格式的秒，需要转换成时间的时间
    Unix时间戳是从1970年1月1日（UTC/GMT的午夜）开始所经过的秒数，不考虑闰秒。
    :param timestamp: 秒数
    :return: 日期格式
    """
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def hex_2_char(hex_str):
    """
    将4个HEX字符串转换成字符
    :param hex_str:
    :return:
    """
    return chr(int(hex_str, 16))


def get_char_from_hex_list(hex_list):
    """
    将字符串数组转换成一组字符串
    :param hen_list:
    :return:
    """
    char_list = ''
    for one_utf16 in hex_list:
        char_list += hex_2_char(one_utf16[2:] + one_utf16[:2])
    return char_list


def hex_str_list_split_2_4_hex_list(data_info, hex_flag_num):
    """
    将一串hex的字符串按照4个hex 一组进行分组 并返回hex_flag_num个0000的序列号，和分好组的list
    :param data_info:
    :param hex_flag_num:
    :return:
    """
    data_info_length = int(len(data_info) / 4)
    data_info_list = []
    for i in range(data_info_length - 1):
        data_info_list.append(data_info[i * 4:i * 4 + 4])
    index_list = []
    for i, one_utf16 in enumerate(data_info_list):
        # '0000' 字符是数据部分 每个字段的分隔符 这里只找两个
        if one_utf16 == '0000':
            index_list.append(i)
        if len(index_list) == hex_flag_num:
            break
    return data_info_list, index_list


def wirting_log_file(log_strs, LOG_NAME):
    """
    将操作记录写到log文件中
    """
    print(log_strs)
    try:
        with open(LOG_NAME, 'a') as f:
            f.write(log_strs+'\n')
        # print('写入完成！')
    except:
        print('日志记录出错！')


def evt_parser(file_path, new_file_path):
    """
    evt文件解析后保存为csv文件
    :param file_path:
    :param new_file_path:
    :return:
    """
    # 二进制格式打开evt文件
    with open(file_path, 'rb') as f:
        #rb是按照二进制格式读取数据
        file_bin = f.read()
    # 文件头部是固定的长度48 bytes
    file_header = file_bin[:header_length]
    if file_header[4:8].hex() == signature:
        print(f'文件头部正确')
    else:
        print(f'文件头部不正确！退出程序！')
        return
    # 文件头部的长度就是每条信息的offset起始位置
    offset = header_length
    # 信息条数记录
    message_counter = 0
    # 定义事件类型字典
    event_type_dict = {
        1: 'Error',
        2: 'Warning',
        4: 'Information',
        8: 'Success Audit',
        16: 'Failure Audit'
    }
    # 定义事件各个字段在这条记录中的相对位置及长度
    content_dict = {
        'length': {'offset': 0, 'size': 4},
        'signature': {'offset': 4, 'size': 4},
        'record_number': {'offset': 8, 'size': 4},
        'time_generated': {'offset': 12, 'size': 4},
        'time_written': {'offset': 16, 'size': 4},
        'event_id': {'offset': 20, 'size': 4},
        'event_type': {'offset': 24, 'size': 2},
        'num_strings': {'offset': 26, 'size': 2},
        'event_category': {'offset': 28, 'size': 2},
        'reserved_flags': {'offset': 30, 'size': 2},
        'closing_record_number': {'offset': 32, 'size': 4},
        # strings_offset是event数据前面的那个描述
        'strings_offset': {'offset': 36, 'size': 4},
        # 如果有user_sid这里记录长度和offset
        'user_sid_length': {'offset': 40, 'size': 4},
        'user_sid_offset': {'offset': 44, 'size': 4},
        # 如果数据这里记录长度和offset
        'data_length': {'offset': 48, 'size': 4},
        'data_offset': {'offset': 52, 'size': 4},
        'source_name': {'offset': 56, 'size': 0},
    }
 
    # 写入csv文件的头部内容
    wirting_str_list = 'Record number,Creation date,Last written date,Event category,Event identifier,Event type,Source name,' \
                       'Computer name,User SID info,Event strings,Event data'
    wirting_log_file(wirting_str_list, new_file_path)
    # 循环处理每一个信息
    while True:
        # 正文内容要一直循环到最后
        message_signature = file_bin[offset + content_dict['signature']['offset']:
                                     offset + content_dict['signature']['offset'] +
                                     content_dict['signature']['size']].hex()
        message_length = hex_2_int(file_bin[offset + content_dict['length']['offset']:
                                            offset + content_dict['length']['offset'] +
                                            content_dict['length']['size']].hex())
        message_counter += 1
        if message_signature == signature:
            # 由于每一个元素的处理方式有差别，所以不能用for循环来处理，只能单个处理

            print(f'第 {message_counter} 个信息标志位正确, 信息长度：{message_length}')
            record_number = hex_2_int(file_bin[offset + content_dict['record_number']['offset']:
                                               offset + content_dict['record_number']['offset'] +
                                               content_dict['record_number']['size']].hex())
            creation_date_time = hex_2_int(file_bin[offset + content_dict['time_generated']['offset']:
                                                    offset + content_dict['time_generated']['offset'] +
                                                    content_dict['time_generated']['size']].hex())
            creation_date_time = timestamp_2_datetime(creation_date_time)
            last_written_date_time = hex_2_int(file_bin[offset + content_dict['time_written']['offset']:
                                                        offset + content_dict['time_written']['offset'] +
                                                        content_dict['time_written']['size']].hex())
            last_written_date_time = timestamp_2_datetime(last_written_date_time)
            event_identifier = int(hex_2_hex(file_bin[offset + content_dict['event_id']['offset']:
                                                      offset + content_dict['event_id']['offset'] +
                                                      content_dict['event_id']['size']].hex())[4:], 16)
            event_type_int = hex_2_int(file_bin[offset + content_dict['event_type']['offset']:
                                                offset + content_dict['event_type']['offset'] +
                                                content_dict['event_type']['size']].hex())
            # 将数字转成报警分类的字符串
            event_type = event_type_dict[event_type_int]
            number_strings = hex_2_int(file_bin[offset + content_dict['num_strings']['offset']:
                                                offset + content_dict['num_strings']['offset'] +
                                                content_dict['num_strings']['size']].hex())
            event_category = hex_2_int(file_bin[offset + content_dict['event_category']['offset']:
                                                offset + content_dict['event_category']['offset'] +
                                                content_dict['event_category']['size']].hex())
            event_flags = hex_2_int(file_bin[offset + content_dict['reserved_flags']['offset']:
                                             offset + content_dict['reserved_flags']['offset'] +
                                             content_dict['reserved_flags']['size']].hex())
            closing_record_number = hex_2_int(file_bin[offset + content_dict['closing_record_number']['offset']:
                                                       offset + content_dict['closing_record_number']['offset'] +
                                                       content_dict['closing_record_number']['size']].hex())
            event_strings_offset = hex_2_int(file_bin[offset + content_dict['strings_offset']['offset']:
                                                      offset + content_dict['strings_offset']['offset'] +
                                                      content_dict['strings_offset']['size']].hex())
            user_identifier_SID_size = hex_2_int(file_bin[offset + content_dict['user_sid_length']['offset']:
                                                          offset + content_dict['user_sid_length']['offset'] +
                                                          content_dict['user_sid_length']['size']].hex())
            user_identifier_SID_offset = hex_2_int(file_bin[offset + content_dict['user_sid_offset']['offset']:
                                                            offset + content_dict['user_sid_offset']['offset'] +
                                                            content_dict['user_sid_offset']['size']].hex())
            event_data_size = hex_2_int(file_bin[offset + content_dict['data_length']['offset']:
                                                 offset + content_dict['data_length']['offset'] +
                                                 content_dict['data_length']['size']].hex())
            event_data_offset = hex_2_int(file_bin[offset + content_dict['data_offset']['offset']:
                                                   offset + content_dict['data_offset']['offset'] +
                                                   content_dict['data_offset']['size']].hex())
            # Event record members
            # 数据部分开始是从 56开始 然后长度是这个数据长度-56 数据最后还是 4个字节的 content_dict['length'] 内容
            data_info = file_bin[offset + content_dict['source_name']['offset']:
                                 offset + content_dict['source_name']['offset'] + (message_length - 56 - 4)].hex()
            # 按照 UTF-16 little-endian 对 data_info进行分组
            data_info_list, index_list = hex_str_list_split_2_4_hex_list(data_info, 2)
            # 解析Source name和 Computer name以后 是否有 User SID 并不确定 有可能有也有可能没有 但是通过 01 01来标志
            source_name = get_char_from_hex_list(data_info_list[:index_list[0]])
            computer_name = get_char_from_hex_list(data_info_list[index_list[0] + 1: index_list[1]])
            # # 记录一下此时 computer_name 最后一个数据的标志位
            # # index_list[1]就是第二个出现 0000的位置 也就是说前面有index_list[1]个4个hex 2个byte
            # offset_after_computer_name = content_dict['source_name']['offset'] + (index_list[1] + 1)*2
            user_sid_str = ''
            if user_identifier_SID_size > 0:
                # 存在user_sid 按照这个格式去解析
                user_sid_data = file_bin[offset + user_identifier_SID_offset:
                                         offset + user_identifier_SID_offset + user_identifier_SID_size].hex()
                user_sid_first_number = int(user_sid_data[:2], 16)
                user_sid_number = int(user_sid_data[2:4], 16)
                user_sid_second_number = int(user_sid_data[4:16], 16)
                user_sid_other_number = user_sid_data[16:]
                # 要判断user_sid_other_number里面有几个数字 一个数据是4个byte也就是8个hex
                user_sid_other_number_list = []
                for i in range(int(len(user_sid_other_number)/8)):
                    user_sid_other_number_list.append(str(hex_2_int(user_sid_other_number[i*8:i*8+8])))
                user_sid_other_number_list_str = '-'.join(user_sid_other_number_list )
                user_sid_str = f'S-{str(user_sid_first_number)}-{str(user_sid_second_number)}-{user_sid_other_number_list_str}'

                # # 如果user_identifier_SID_size也就是user_identifier_SID_size有内容 需要将 offset_after_computer_name继续向后移动
                # offset_after_computer_name += user_identifier_SID_size
            # 查看event_strings的内容
            event_strings_code_list = []
            if number_strings > 0:
                event_strings = file_bin[offset + event_strings_offset:offset + event_data_offset].hex()
                event_strings_list, event_strings_index_list = hex_str_list_split_2_4_hex_list(event_strings, number_strings)
                # 定义最后一个元素的起始index  如果   len(event_strings_index_list) = 0 则取event_strings_list的全部
                final_index = 0
                if len(event_strings_index_list) > 0:
                    # 如果event_strings元素个数只有一个的时候   event_strings_index_list是没有内容的 只有多个的时候才执行后面内容
                    # 有多个字符串的时候 需要定义最初始的开始结束index 然后每次循环后更新
                    start_index = 0
                    end_index = event_strings_index_list[0]
                    for i in range(len(event_strings_index_list)):
                        # 有多个字符串的时候
                        event_strings_code_list.append(get_char_from_hex_list(event_strings_list[start_index:end_index]))
                        start_index = end_index+1
                        if i+1 < len(event_strings_index_list):
                            # 这里要注意的是通过event_strings_offset到 event_data_offset获得的数据 最后是没有 0000的
                            # 所以number_strings的数字 比len(event_strings_index_list) 要大一个
                            # 这里只能取到 event_strings_index_list的最后一个数据
                            end_index = event_strings_index_list[i+1]
                    # 更新最后一个元素的起始index
                    final_index = event_strings_index_list[-1] + 1
                # 最后一组
                event_strings_code_list.append(get_char_from_hex_list(event_strings_list[final_index:]))
            event_data = ''
            if event_data_size > 0:
                # 存在user_sid 按照这个格式去解析
                event_data = file_bin[offset + event_data_offset:
                                      offset + event_data_offset + event_data_size].hex()
                # 把event_data直接按照4个一组进行分组
                event_data_list = [event_data[i*4:i*4+4] for i in range(int(len(event_data)/4))]
                event_data_str = get_char_from_hex_list(event_data_list)
            # Record number,Creation date,Last written date,Event identifier,Event type,Source name,
            # Computer name,User SID info,Event strings,Event data
            wirting_str_list = f'{str(record_number)},{str(creation_date_time)},{str(last_written_date_time)},{str(event_category)},' \
                               f'{str(event_identifier)},{str(event_type)},' \
                               f'{source_name},{computer_name},{user_sid_str},' \
                               f'{str(" ".join(event_strings_code_list))},{str(event_data)}'

            wirting_log_file(wirting_str_list, new_file_path)

        elif message_signature == end_signature_1:
            record_number = file_bin[offset + content_dict['record_number']['offset']:
                                     offset + content_dict['record_number']['offset'] +
                                     content_dict['record_number']['size']].hex()
            if record_number == end_signature_2:
                print(f'文件信息结束！')
                break
        else:
            print(f'第 {message_counter} 个信息标志位错误！')
        offset += message_length


signature = '4c664c65'
end_signature_1 = '11111111'
end_signature_2 = '22222222'
header_length = 48

file_path = r''
# file_dict存放文件的路径和文件名（key），及保持文件为csv格式的路径和文件名(value)
file_dict = {}
for file in os.listdir(file_path):
    file_name_path = os.path.join(file_path, file)
    file_name_part1, file_name_part2 = os.path.splitext(file)
    if os.path.isfile(file_name_path) and file_name_part2 == '.evt':
        file_dict[file_name_path] = os.path.join(file_path, file_name_part1 + '.csv')

for key, value in file_dict.items():
    try:
        evt_parser(key, value)
        print(f'{key} 文件解析完成！')
    except:
        print(f'{key} 文件解析失败！')
        continue

