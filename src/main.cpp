#include <iostream>
#include <string>

#include <boost/asio.hpp>

#include <blowfish/blowfish.h>

using boost::asio::ip::tcp;

void start_tcp_server()
{
    try
    {
        boost::asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 2106));

        std::cout << "TCP server started on port 2106" << std::endl;

        while (true)
        {
            tcp::socket socket(io_context);
            acceptor.accept(socket);

            std::cout << "Client connected from: " << socket.remote_endpoint() << std::endl;

            // Keep connection open until client disconnects
            try
            {
                char data[1024];
                boost::system::error_code error;

                while (true)
                {
                    size_t length = socket.read_some(boost::asio::buffer(data), error);
                    if (error == boost::asio::error::eof)
                        break; // Connection closed cleanly by peer
                    else if (error)
                        throw boost::system::system_error(error);
                }
            }
            catch (std::exception &e)
            {
                std::cout << "Connection error: " << e.what() << std::endl;
            }

            std::cout << "Client disconnected" << std::endl;
        }
    }
    catch (std::exception &e)
    {
        std::cerr << "Server error: " << e.what() << std::endl;
    }
}

int main()
{
    std::cout << "\nStarting TCP server..." << std::endl;
    start_tcp_server();

    return 0;
}
