// SPDX-License-Identifier: MIT
// gcc -o prob prob.c
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bits/stdc++.h>

using namespace std;

class Allocator {

public:
    typedef struct Chunk {
        uint64_t priv_size;
        uint64_t curr_size;
        char data[];
    }Chunk;
    
private:
    void *Base;
    void *Top;
    uint64_t bound;

    vector<set<Chunk *>> Bins;
    int debugmode;

    uint64_t ALIGN(uint64_t size) {
        size += sizeof(Chunk);
        size = (size % 0x10) ? (size&(~0xf))+0x10 : size;
        return (size > 0x20 ? size : 0x20);
    }
    
    bool IS_TopChunk(Chunk *chunk) {
        return Top == chunk;
    }

    bool IS_Base(Chunk *chunk) {
        return chunk == Base;
    }

    bool IS_Aligned(Chunk *chunk) {
        return !((uint64_t)chunk & 0xf);
    }

    bool IS_PrevInuse(Chunk *chunk) {
        return chunk->curr_size&0x1;
    }

    bool IS_NextInuse(Chunk *chunk) {
        return NextChunk(NextChunk(chunk))->curr_size & 0x1;
    }

    void On_PrevInuse(Chunk *chunk) {
        chunk->curr_size |= 0x1;
    }

    void Off_PrevInuse(Chunk *chunk) {
        chunk->curr_size &= ~0x1;
    }

    uint64_t PrivSize(Chunk *chunk) {
        return chunk->priv_size & (~0xf);
    }

    uint64_t SIZE(Chunk *chunk) {
        return chunk->curr_size & (~0xf);
    }

    Chunk *PrivChunk(Chunk *chunk) {
        return (Chunk *)((uint64_t)chunk - PrivSize(chunk));
    }

    Chunk *NextChunk(Chunk *chunk) {
        return (Chunk *)((uint64_t)chunk + SIZE(chunk));
    }

    char *Chunk_to_Data(Chunk *chunk) {
        return (char *)(chunk->data);
    }

    Chunk *Data_to_Chunk(void *ptr) {
        return (Chunk *)((uint64_t)ptr - sizeof(Chunk));
    }

    static bool Chunk_Size_Cmp(Chunk *l, Chunk *r) {
        return (l->curr_size < r->curr_size ? true : false);
    }

    bool IS_IN_Bins(Chunk *freechunk) {
        int idx = size_to_idx(SIZE(freechunk));
        if(Bins[idx].find(freechunk) == Bins[idx].end())
            return false;
        return true;
    }

    void Allocator_assertion(const char *errmsg) {
        cout << errmsg << endl;
        exit(-1);
    }

    uint64_t size_to_idx(uint64_t size) {
        int idx = 0;

        size /= 0x20;

        while(size > 1 && idx < 10) {
            size >>= 1;
            idx++;
        }
        
        return (idx < 10 ? idx : 9);
    }

    Chunk *Split_Chunk(Chunk *chunk, uint64_t upsize) {
        return (Chunk *)((uint64_t)chunk + upsize);
    }

    void Put_into_Bins(Chunk *chunk) {

        if(debugmode) {
            printf("Top: 0x%llx\n", Top);
            printf("curr: 0x%llx, next: 0x%llx, nextsize: 0x%llx\n", chunk, NextChunk(chunk), SIZE(NextChunk(chunk)));
            fflush(stdout);
        }

        if(!IS_PrevInuse(chunk) || (!IS_TopChunk(NextChunk(chunk)) && !IS_NextInuse(chunk)))
            chunk = internal_consolidate_chunk(chunk);

        if(chunk != nullptr) {
            if(IS_TopChunk(NextChunk(chunk))) { 
                chunk->curr_size += ((Chunk *)Top)->curr_size;
                Top = (void *)chunk;
            }
            else {
                Off_PrevInuse(NextChunk(chunk));
                int start_idx = size_to_idx(SIZE(chunk));
                Bins[start_idx].insert(chunk);
            }
        }
    }

    void Pop_from_Bins(Chunk *chunk) {

        if(chunk != nullptr) {
            int start_idx = size_to_idx(SIZE(chunk));
            Bins[start_idx].erase(chunk);
        }
    }

    Chunk *internal_consolidate_chunk(Chunk *newchunk) {
        Chunk *lowest = newchunk;
        Chunk *higest = newchunk;

        uint64_t newsize = SIZE(newchunk);

        while(!IS_Base(lowest) && !IS_PrevInuse(lowest)) {
            if(debugmode) {
                printf("consolidate: 0x%llx\n", PrivChunk(lowest));
            }
            Pop_from_Bins(PrivChunk(lowest));
            lowest = PrivChunk(lowest);
            newsize += SIZE(lowest);
        }
        
        while(!IS_TopChunk(NextChunk(higest)) && !IS_NextInuse(higest)) {
            if(debugmode) {
                printf("consolidate: 0x%llx\n", NextChunk(higest));
            }
            Pop_from_Bins(NextChunk(higest));
            higest = NextChunk(higest);
            newsize += SIZE(higest);
        }

        if(IS_TopChunk(NextChunk(higest))) {
            lowest->curr_size = newsize + SIZE((Chunk *)Top);
            Top = lowest;
            return nullptr;
        }
        else {
            lowest->curr_size = newsize;
            NextChunk(lowest)->priv_size = SIZE(newchunk);
        }
        On_PrevInuse(lowest);
        Off_PrevInuse(NextChunk(lowest));

        return lowest;
    }

    char *internal_split_chunk_allocator(Chunk *newchunk, uint64_t aligned_size) {
        if( SIZE(newchunk) - aligned_size < 0x20) {
            On_PrevInuse(NextChunk(newchunk));
            return Chunk_to_Data(newchunk);
        }
        else {
            bool before_priv_inuse = IS_PrevInuse(newchunk);
            Chunk *ret_newchunk = newchunk;
            Chunk *splited_chunk = Split_Chunk(newchunk, aligned_size);

            if(debugmode) {
                printf("split_mode: 0x%llx, 0x%llx\n", ret_newchunk, splited_chunk);
            }

            splited_chunk->curr_size = SIZE(newchunk) - aligned_size;
            splited_chunk->priv_size = aligned_size;

            ret_newchunk->curr_size = aligned_size;

            On_PrevInuse(splited_chunk);
            if(before_priv_inuse)
                On_PrevInuse(ret_newchunk);
            else
                Off_PrevInuse(ret_newchunk);
            
            Put_into_Bins(splited_chunk);

            return Chunk_to_Data(ret_newchunk);
        }
    }

    char *internal_top_region_allocator(uint64_t aligned_size) {
        if(SIZE((Chunk *)Top) < aligned_size)
            return nullptr;
        else {
            Chunk *newchunk = (Chunk *)Top;
            uint64_t priv_top_size = SIZE((Chunk *)Top);
            uint64_t top_priv_inuse = IS_PrevInuse((Chunk *)Top);
            
            Top = (void *)((uint64_t)Top + aligned_size);
            ((Chunk *)Top)->curr_size = priv_top_size - aligned_size;
            ((Chunk *)Top)->priv_size = aligned_size;

            newchunk->curr_size = aligned_size;

            On_PrevInuse((Chunk *)Top);
            if(top_priv_inuse)
                On_PrevInuse(newchunk);
            else
                Off_PrevInuse(newchunk);
            
            return Chunk_to_Data(newchunk);
        }
    }

public:

    Allocator(){
        int urandom_fd;
        debugmode = 0;
        uint64_t addr = 0;
        
        if ( ( urandom_fd = open("/dev/urandom", O_RDONLY) ) < 0 ) {
            perror("failed to open /dev/urandom");
            exit(-1);
        }
        read(urandom_fd, &addr, 4);
        addr <<= 16;
        addr = addr & 0xfffffffffff;

        close(urandom_fd);
        
        if ( ( Top = mmap( (void *)addr, 1<<30, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0 ) ) != (void *)addr ) {
            perror("failed to alloc HEAP region");
            exit(-1);
        }
        Base = Top;

        bound = addr + (1<<26);
        ((Chunk *)Top)->priv_size = 0;
        ((Chunk *)Top)->curr_size = (1 << 26) + 1;

        Bins.resize(10, set<Chunk *>());
    }

    ~Allocator() {
        munmap(Top, (1<<26));
    }

    char *malloc(uint64_t size) {
        uint64_t aligned_size = ALIGN(size);

        Chunk *chunk = nullptr;
        int start_idx = size_to_idx(aligned_size);
        Chunk tmp = { 
            .curr_size = aligned_size
        };

        if(debugmode) {
            printf("try to alloc 0x%llx size chunk\n", aligned_size);
        }

        for(auto bin = next(Bins.begin(), start_idx); bin != Bins.end(); bin++) {
            auto newchunk = lower_bound((*bin).begin(), (*bin).end(), &tmp, Chunk_Size_Cmp);
            if(newchunk == (*bin).end())
                continue;

            chunk = *newchunk;
            (*bin).erase(newchunk);
            break;
        }
        if(debugmode) {
            if(chunk)
                printf("found some bin, 0x%llx\n", chunk);
        }

        if(chunk)
            return internal_split_chunk_allocator(chunk, aligned_size);
        else
            return internal_top_region_allocator(aligned_size);
    }
    
    void free(void *ptr) {
        if(!ptr)
            return;
        Chunk *freechunk = Data_to_Chunk(ptr);
        if(debugmode)
            printf("free: 0x%llx, size: 0x%llx\n", freechunk, SIZE(freechunk));

        Put_into_Bins(freechunk);
    }

    void CheckHeapSanity() {
        Chunk *start = (Chunk *)Base;
        while(!IS_TopChunk(start))
        {
            printf("addr: 0x%llx, size: 0x%llx\n", start, SIZE(start));
            fflush(stdout);
            start = NextChunk(start);
            if(start > (Chunk *)Top)
                Allocator_assertion("Chunk Corrupted");
        }
        printf("top: 0x%llx\n", Top);
    }

    void debug_on() {
        debugmode = 1;
    }
};

#define MAX_MAILS 0x21
#define MAX_USER 10

typedef struct Mail {
    uint32_t to;
    uint32_t from;
    uint64_t textlen;
    char *info;
} Mail;

typedef struct Mails {
    uint8_t send_front;
    uint8_t send_rear;
    Mail *send_queue[MAX_MAILS];
    
    uint8_t recv_front;
    uint8_t recv_rear;
    Mail *recv_queue[MAX_MAILS];
} Mails;

typedef struct Mailbox {
    Mails* mailbox[10];
} Mailbox;

Mailbox *mailbox;
Allocator Cage;

bool check_user_exist(uint32_t user) {
    if(mailbox->mailbox[user] == nullptr)
        return false;
    return true;
}

void make_message(uint32_t user) {
    Mails* mails = mailbox->mailbox[user];

    if((mails->send_rear+1) % MAX_MAILS == mails->send_front)
        cout << "send queue is full" << endl;
    else {
        uint64_t textlen; 
        cout << "Text size: ";
        cin >> textlen;

        mails->send_rear = (mails->send_rear+1)%MAX_MAILS;

        mails->send_queue[mails->send_rear] = (Mail *)Cage.malloc(sizeof(Mail));
        mails->send_queue[mails->send_rear]->info = (char *)Cage.malloc(textlen + 1);
        if(mails->send_queue[mails->send_rear]->info == nullptr)
        {
            cout << "allocation failed" << endl;
            return;
        }
        cout << "message: ";
        
        uint64_t reallen;
        reallen = read(0, mails->send_queue[mails->send_rear]->info, textlen);
        mails->send_queue[mails->send_rear]->textlen = (reallen < 0 ? 0 : reallen);
    }
}

void read_message(uint32_t user) {
    Mails* mails = mailbox->mailbox[user];

    if(mails->recv_front == mails->recv_rear)
        cout << "recv queue is empty" << endl;
    else {
        mails->recv_front = (mails->recv_front+1)%MAX_MAILS;

        cout << "from: " << mails->recv_queue[mails->recv_front]->from << endl;
        cout << "to: " << mails->recv_queue[mails->recv_front]->to << endl;
        cout << "text: ";
        write(1, mails->recv_queue[mails->recv_front]->info, mails->recv_queue[mails->recv_front]->textlen);

        string c;
        cout << "erase message? ";
        cin >> c;
        if(c == "y" || c == "Y")
        {
            Cage.free(mails->recv_queue[mails->recv_front]->info);
            Cage.free(mails->recv_queue[mails->recv_front]);
        }
    }
}

void send_message(uint32_t user) {
    Mails* mails_from = mailbox->mailbox[user];

    if(mails_from->send_front == mails_from->send_rear)
        cout << "Send queue is empty" << endl;
    else {
        uint32_t to;
        cout << "to: ";
        scanf("%u*c", &to);

        if(to >= MAX_USER) {
            cout << "Invalid user index" << endl;
            return;
        }
        if(!check_user_exist(to)) {
            cout << "user not exist" << endl;
            return;
        }

        Mails *mails_to = mailbox->mailbox[to];

        if((mails_to->recv_rear+1) % MAX_MAILS == mails_to->recv_front)
            cout << "Recv queue is full" << endl;
        else {
            mails_from->send_front = (mails_from->send_front+1) % MAX_MAILS;
            mails_to->recv_rear = (mails_to->recv_rear+1) % MAX_MAILS;
            mails_to->recv_queue[mails_to->recv_rear] = mails_from->send_queue[mails_from->send_front];
            mails_to->recv_queue[mails_to->recv_rear]->from = user;
            mails_to->recv_queue[mails_to->recv_rear]->to = to;

            cout << "Send message " << mails_to->recv_queue[mails_to->recv_rear]->from << " -> " << mails_to->recv_queue[mails_to->recv_rear]->to << endl; 
        }
    }
}

void discard_user(int user) {
    if(mailbox->mailbox[user]->send_front == mailbox->mailbox[user]->send_rear) {
        if(mailbox->mailbox[user]->recv_front == mailbox->mailbox[user]->recv_rear) {
            Cage.free(mailbox->mailbox[user]);
            mailbox->mailbox[user] = nullptr;
            return;
        }
        else {
            cout << "send queue is empty but recv queue is not empty" << endl;
            return;
        }
    }
    else {
        cout << "send queue is not empty" << endl;
        return;
    }
}

int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    mailbox = (Mailbox *)Cage.malloc(sizeof(Mailbox));
    for(int i=0; i<MAX_USER; i++)
        mailbox->mailbox[i] = nullptr;
    
    uint32_t user = 0;
    cout << "Welcome to Sandnote!" << endl;
    while(true) {
        int cmd;
        cout << "cmd > ";
        cin >> cmd;

        switch(cmd) {
            case 0:
                cout << "Change User: ";
                cin >> user;

                if(user > 9) {
                    cout << "Invalid User Idx" << endl;
                    exit(-1);
                }
                if(mailbox->mailbox[user] == nullptr)
                {
                    mailbox->mailbox[user] = (Mails *)Cage.malloc(sizeof(Mails));
                    mailbox->mailbox[user]->send_front = mailbox->mailbox[user]->send_rear = 0;
                    mailbox->mailbox[user]->recv_front = mailbox->mailbox[user]->recv_rear = 0;
                }

                cout << "You are now " << user << endl;
                break;

            case 1:
                if(!check_user_exist(user)) {
                    cout << "user not exist" << endl;
                    break;
                }
                make_message(user);
                break;

            case 2:
                if(!check_user_exist(user)) {
                    cout << "user not exist" << endl;
                    break;
                }
                read_message(user);
                break;

            case 3:
                if(!check_user_exist(user)) {
                    cout << "user not exist" << endl;
                    break;
                }
                send_message(user);
                break;

            case 4:
                if(!check_user_exist(user)) {
                    cout << "user not exist" << endl;
                    break;
                }
                discard_user(user);
                break;

            case 5:
                exit(0);

            default:
                cout << "invalid cmd!" << endl;
        }
    }
}