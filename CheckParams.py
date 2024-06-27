from core import requester
from core import extractor
from core import save_it
from urllib.parse import unquote
import requests
import re
import argparse
import os
import sys
import time

start_time = time.time()

def main():
    if os.name == 'nt':
        os.system('cls')
    banner = """\u001b[36m

     _   _       _     _            _   _               _    
    | | | | ___ | |___| |_ ___     | |_| | ___  _ __   (_)___
    | |_| |/ _ \| / __| __/ _ \    | __| |/ _ \| '_ \  | / __|
     \__\_/\___/_/\__|_|_\___/     |_| |_|\___/|_| |_| |_\__|

                          \u001b[32m - FuzzCheck by Mftheux\u001b[0m 
    """
    print(banner)

    parser = argparse.ArgumentParser(description='Descoberta de parâmetros para poc XSS')
    parser.add_argument('-d', '--domain', help='Nome de domínio do alvo [ex : exemplo.com.br]', required=True)
    parser.add_argument('-s', '--subs', help='Defina Falso para não substituir [ex : --subs False ]', default=True)
    parser.add_argument('-l', '--level', help='Para parâmetros aninhados [ex : --level high]')
    parser.add_argument('-e', '--exclude', help='Extensões para excluir [ex --exclude php,aspx]')
    parser.add_argument('-o', '--output', help='Nome do arquivo de saída [por padrão é  \'domain.txt\']')
    parser.add_argument('-p', '--placeholder', help='A string para adicionar como placeholder após o nome do parâmetro.',
                        default="FUZZ")
    parser.add_argument('-q', '--quiet', help='Não imprima os resultados na tela', action='store_true')
    parser.add_argument('-r', '--retries', help='Especifique o número de tentativas para erros 4xx e 5xx', default=3)
    args = parser.parse_args()

    if args.subs == True or " True":
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{args.domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
    else:
        url = f"https://web.archive.org/cdx/search/cdx?url={args.domain}/*&output=txt&fl=original&collapse=urlkey&page=/"

    retry = True
    retries = 0
    while retry == True and retries <= int(args.retries):
        response, retry = requester.connector(url)
        retry = retry
        retries += 1
    if response == False:
        return
    response = unquote(response)

    # para extensões a serem excluídas
    black_list = []
    if args.exclude:
        if "," in args.exclude:
            black_list = args.exclude.split(",")
            for i in range(len(black_list)):
                black_list[i] = "." + black_list[i]
        else:
            black_list.append("." + args.exclude)

    else:
        black_list = []  # for blacklists
    if args.exclude:
        print(
            f"\u001b[31m[!] URLs contendo essas extensões serão excluídas dos resultados. : {black_list}\u001b[0m\n")

    # Optimizado para extrair com set para encontrar URLs únicas mais rápido
    final_uris = set(extractor.param_extract(response, args.level, black_list, args.placeholder))
    save_it.save_func(final_uris, args.output, args.domain)

    if not args.quiet:
        print("\u001b[32;1m")
        print('\n'.join(final_uris))
        print("\u001b[0m")

    print(f"\n\u001b[32m[+] Número total de tentativas: {retries - 1}\u001b[31m")
    print(f"\u001b[32m[+] Total de URLs exclusivas encontradas: {len(final_uris)}\u001b[31m")
    if args.output:
        if "/" in args.output:
            print(f"\u001b[32m[+] A saída é salva aqui :\u001b[31m \u001b[36m{args.output}\u001b[31m")

        else:
            print(f"\u001b[32m[+] A saída é salva aqui :\u001b[31m \u001b[36moutput/{args.output}\u001b[31m")
    else:
        print(f"\u001b[32m[+] A saída é salva aqui   :\u001b[31m \u001b[36moutput/{args.domain}.txt\u001b[31m")
    print("\n\u001b[31m[!] tempo total de execução     : %ss\u001b[0m" % str((time.time() - start_time))[:-12])


if __name__ == "__main__":
    main()
