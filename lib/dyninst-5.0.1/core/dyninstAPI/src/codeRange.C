/*
 * Copyright (c) 1996-2004 Barton P. Miller
 * 
 * We provide the Paradyn Parallel Performance Tools (below
 * described as "Paradyn") on an AS IS basis, and do not warrant its
 * validity or performance.  We reserve the right to update, modify,
 * or discontinue this software at any time.  We shall have no
 * obligation to supply such updates or modifications or any other
 * form of support to you.
 * 
 * This license is for research uses.  For such uses, there is no
 * charge. We define "research use" to mean you may freely use it
 * inside your organization for whatever purposes you see fit. But you
 * may not re-distribute Paradyn or parts of Paradyn, in any form
 * source or binary (including derivatives), electronic or otherwise,
 * to any other organization or entity without our permission.
 * 
 * (for other uses, please contact us at paradyn@cs.wisc.edu)
 * 
 * All warranties, including without limitation, any warranty of
 * merchantability or fitness for a particular purpose, are hereby
 * excluded
 * 
 * By your use of Paradyn, you understand and agree that we (or any
 * other person or entity with proprietary rights in Paradyn) are
 * under no obligation to provide either maintenance services,
 * update services, notices of latent defects, or correction of
 * defects for Paradyn.
 * 
 * Even if advised of the possibility of such damages, under no
 * circumstances shall we (or any other person or entity with
 * proprietary rights in the software licensed hereunder) be liable
 * to you or any third party for direct, indirect, or consequential
 * damages of any character regardless of type of action, including,
 * without limitation, loss of profits, loss of use, loss of good
 * will, or computer failure or malfunction.  You agree to indemnify
 * us (and any other person or entity with proprietary rights in the
 * software licensed hereunder) for any and all liability it may
 * incur to third parties resulting from your use of Paradyn.
 */

// $Id: codeRange.C,v 1.20 2006/05/30 23:34:00 mjbrim Exp $

#include <stdio.h>
#include "codeRange.h"

#include "dyninstAPI/src/symtab.h"
#include "dyninstAPI/src/baseTramp.h"
#include "dyninstAPI/src/miniTramp.h"
#include "dyninstAPI/src/mapped_object.h"
#include "dyninstAPI/src/function.h"
#include "dyninstAPI/src/instPoint.h"
#include "dyninstAPI/src/rpcMgr.h"

multiTramp *codeRange::is_multitramp() {
    if (dynamic_cast<multiTramp *>(this))
        return dynamic_cast<multiTramp *>(this);
    else if (dynamic_cast<instArea *>(this))
        return (dynamic_cast<instArea *>(this))->multi;
    return NULL;
}

inferiorRPCinProgress * codeRange::is_inferior_rpc() {
	return dynamic_cast< inferiorRPCinProgress * >( this );
	}

// This is a special case... the multitramp is the thing in the
// codeRange tree, but people think of baseTramps.
// So this is dangerous to use, actually.
baseTrampInstance *codeRange::is_basetramp_multi() {
   return dynamic_cast<baseTrampInstance *>(this);
}

miniTrampInstance *codeRange::is_minitramp() {
   return dynamic_cast<miniTrampInstance *>(this);
}

bblInstance *codeRange::is_basicBlockInstance() {
    return dynamic_cast<bblInstance *>(this);
}

int_basicBlock *codeRange::is_basicBlock() {
    bblInstance *block = dynamic_cast<bblInstance *>(this);
    if (block)
        return block->block();
    return NULL;
}

int_function *codeRange::is_function() {
    bblInstance *block = dynamic_cast<bblInstance *>(this);
    if (block)
        return block->func();
    return NULL;
}

image_func *codeRange::is_image_func() {
   return dynamic_cast<image_func *>(this);
}

image_basicBlock *codeRange::is_image_basicBlock() {
    return dynamic_cast<image_basicBlock *>(this);
}

replacedFunctionCall *codeRange::is_replaced_call() {
    return dynamic_cast<replacedFunctionCall *>(this);
}

functionReplacement *codeRange::is_function_replacement() {
    return dynamic_cast<functionReplacement *>(this);
}


image *codeRange::is_image() {
   return dynamic_cast<image *>(this);
}

mapped_object *codeRange::is_mapped_object() {
   return dynamic_cast<mapped_object *>(this);
}

void codeRangeTree::leftRotate(entry* pivot){
	if(!pivot || (pivot == nil))
		return;
	entry* y = pivot->right;
	if(y == nil)
		return;
	pivot->right = y->left;
	if(y->left != nil)
		y->left->parent = pivot;
	y->parent = pivot->parent;
	if(!pivot->parent) {
		setData = y;
        }
	else if(pivot == pivot->parent->left)
		pivot->parent->left = y;
	else
		pivot->parent->right = y;
	y->left = pivot;
	pivot->parent = y;
}


void codeRangeTree::rightRotate(entry* pivot){
	if(!pivot || (pivot == nil))
		return;
	entry* x = pivot->left;
	if(x == nil)
		return;
	pivot->left = x->right;
	if(x->right != nil)
		x->right->parent = pivot;
	x->parent = pivot->parent;
	if(!pivot->parent) {
		setData = x;
        }
	else if(pivot == pivot->parent->left)
		pivot->parent->left = x;
	else
		pivot->parent->right = x;
	x->right = pivot;
	pivot->parent = x;
}


void codeRangeTree::deleteFixup(entry* x){
	while((x != setData) && 
	      (x->color == TREE_BLACK))
	{
		if(x == x->parent->left){
			entry* w = x->parent->right;
			if(w->color == TREE_RED){
				w->color = TREE_BLACK;
				x->parent->color = TREE_RED;
				leftRotate(x->parent);
				w = x->parent->right;
			}
			if((w->left->color == TREE_BLACK) &&
			   (w->right->color == TREE_BLACK)){
				w->color = TREE_RED;
				x = x->parent;
			}
			else{
				if(w->right->color == TREE_BLACK){
					w->left->color = TREE_BLACK;
					w->color = TREE_RED;
					rightRotate(w);
					w = x->parent->right;
				}
				w->color = x->parent->color;
				x->parent->color = TREE_BLACK;
				w->right->color = TREE_BLACK;
				leftRotate(x->parent);
				x = setData;
			}
		}
		else{
			entry* w = x->parent->left;
			if(w->color == TREE_RED){
				w->color = TREE_BLACK;
				x->parent->color = TREE_RED;
				rightRotate(x->parent);
				w = x->parent->left;
			}
			if((w->right->color == TREE_BLACK) &&
			   (w->left->color == TREE_BLACK)){
				w->color = TREE_RED;
				x = x->parent;
			}
			else{
				if(w->left->color == TREE_BLACK){
					w->right->color = TREE_BLACK;
					w->color = TREE_RED;
					leftRotate(w);
					w = x->parent->left;
				}
				w->color = x->parent->color;
				x->parent->color = TREE_BLACK;
				w->left->color = TREE_BLACK;
				rightRotate(x->parent);
				x = setData;
			}
		}
	}
	x->color = TREE_BLACK;
}


codeRangeTree::entry *codeRangeTree::treeInsert(Address key, codeRange *value)
{
	entry* y = NULL;
	entry* x = setData;
	while(x != nil){
		y = x;
                if (key < x->key) 
                    x = x->left;
                else if(key > x->key)
                    x = x->right;
                else
                    return NULL;
	}	
	entry* z = new entry(key, value, nil);
	z->parent = y;
	if(!y) {
		setData = z;
        }
	else {
        if (key < y->key)
            y->left = z;
		else if (key > y->key)
			y->right = z;
	}
	setSize++;
	return z;
}

/** finds the minimum value node when x is being deleted */

codeRangeTree::entry *codeRangeTree::treeSuccessor(entry* x) const{
	if(!x || (x == nil))
		return NULL;
	if(x->right != nil){
		entry* z = x->right;
		while(z->left != nil) z = z->left;
		return z;
	}
	entry* y = x->parent;
	while(y && (x == y->right)){
		x = y;
		y = y->parent;
	}
	return y;
}


codeRangeTree::entry *codeRangeTree::find_internal(Address element) const{
	entry* x = setData;
	while(x != nil){
            if (element < x->key) {
                x = x->left;
            }
            else if (element > x->key) {
                x = x->right;
            }
            else
                return x;
	}	
	return NULL;
}


void codeRangeTree::traverse(codeRange ** all, entry* node, int& n) const{
	if(node == nil)
		return;
	if(node->left != nil)
		traverse(all,node->left,n);
	if(all)
		all[n++] = node->value;
	if(node->right != nil)
		traverse(all,node->right,n);
}


void codeRangeTree::traverse(pdvector<codeRange *> &all, entry* node) const{
	if(node == nil)
		return;
	if(node->left != nil)
		traverse(all,node->left);
        all.push_back(node->value);
	if(node->right != nil)
		traverse(all,node->right);
}

//////////////////////////// PUBLIC FUNCTIONS ////////////////////////////////

void codeRangeTree::insert(codeRange *value) {
 	entry* x = treeInsert(value->get_address_cr(), value);
	if(!x) {
         // We're done.
         return;
    }
	x->color = TREE_RED;
	while((x != setData) && (x->parent->color == TREE_RED)){
		if(x->parent == x->parent->parent->left){
			entry* y = x->parent->parent->right;
			if(y->color == TREE_RED){
				x->parent->color = TREE_BLACK;
				y->color = TREE_BLACK;
				x->parent->parent->color = TREE_RED;
				x = x->parent->parent;
			}
			else{
				if(x == x->parent->right){
					x = x->parent;
					leftRotate(x);
				}
				x->parent->color = TREE_BLACK;
				x->parent->parent->color = TREE_RED;
				rightRotate(x->parent->parent);
			}
		}
		else{
			entry* y = x->parent->parent->left;
			if(y->color == TREE_RED){
				x->parent->color = TREE_BLACK;
				y->color = TREE_BLACK;
				x->parent->parent->color = TREE_RED;
				x = x->parent->parent;
			}
			else{
				if(x == x->parent->left){
					x = x->parent;
					rightRotate(x);
				}
				x->parent->color = TREE_BLACK;
				x->parent->parent->color = TREE_RED;
				leftRotate(x->parent->parent);
			}
		}
	}
	setData->color = TREE_BLACK;
}

 void codeRangeTree::remove(Address key){
	entry* z = find_internal(key);
	if(!z)
            return;
        if (z->key != key)
            return;

	entry* y=((z->left == nil)||(z->right == nil)) ? z : treeSuccessor(z);
	entry* x=(y->left != nil) ? y->left : y->right;
	x->parent = y->parent;
	if(!y->parent) {
		setData = x;
        }
	else if(y == y->parent->left)
		y->parent->left = x;
	else
		y->parent->right = x;
	if(y != z) {
		z->value = y->value;
        z->key = y->key;
    }
	if(y->color == TREE_BLACK)
		deleteFixup(x);
	setSize--;
	delete y;
}




void codeRangeTree::destroy(entry* node){
	if(!node || (node == nil))
		return;
	if(node->left != nil)
		destroy(node->left);
	if(node->right != nil)
		destroy(node->right);
	delete node;
}

bool codeRangeTree::find(Address key, codeRange *& value) const{
    value = NULL;
    if (!precessor(key, value))
        return false;
    // Check to see if the range works
    if (!value->get_size_cr()) {
        // XXX do we really need this warning?
        //fprintf(stderr, "%s[%d]:  Warning:  size was 0...\n", FILE__, __LINE__);
        if(key > value->get_address_cr())
            return false;
    }
    else if(key >= (value->get_address_cr() + value->get_size_cr())) {
        return false;
    }
    // We can also underflow
    if (key < value->get_address_cr())
        return false;
    return true;
#if 0
    fprintf(stderr, "codeRangeTree::find for 0x%x\n", key);
    entry* x = find_internal(key);
    fprintf(stderr, "find_internal returned %p\n", x);
    if (!x) return false;
    value = x->value;
    assert(value->get_address_cr() <= key); // Otherwise it wouldn't have been returned.

    if (key >= (value->get_address_cr() + value->get_size_cr())) {
        fprintf(stderr, "... ret false\n");
        return false;
    }
    fprintf(stderr, "... ret true\n");
    return true;
#endif
}

bool codeRangeTree::precessor(Address key, codeRange * &value) const{
    entry *x = setData;
    entry *last = nil;
    while (x != nil) {
        assert(x != NULL);
        if (x->key == key) {
            value = x->value;
            return true;
        }
        else if (key < x->key) {
            x = x->left;
        }
        else { // key > x->key
            last = x;
            x = x->right;
        }
    }
    if (x == nil) {
        // Ran out of tree to search... get the parent
        assert(last != NULL);
        if (last != nil) {
            value = last->value;
            return true;
        }
        else return false;
    }
    // Should never hit here
    assert(0);
    return false;
}

bool codeRangeTree::successor(Address key, codeRange * &value) const{
    entry *x = setData;
    entry *last = nil;
    while (x != nil) {
        if (x->key == key) {
            value = x->value;
            return true;
        }
        else if (key > x->key) {
            x = x->right;
        }
        else { // key < x->key
            last = x;
            x = x->left;
        }
    }
    if (x == nil) {
        // Ran out of tree to search... get the parent
        if (last != nil) {
            value = last->value;
            return true;
        }
        else return false;
    }
    // Should never reach this point
    assert(0);
    return false;
}

codeRange ** codeRangeTree::elements(codeRange ** buffer) const{
	if(setData == nil) return NULL;
	if(!buffer) return NULL;
	int tmp = 0;
	traverse(buffer,setData,tmp);	
	return buffer;
}

bool codeRangeTree::elements(pdvector<codeRange *> &buffer) const{
	if(setData == nil) return false;
	traverse(buffer,setData);	
        return true;
}

void codeRangeTree::clear() {
    if (setData == nil) return;
    destroy(setData);
    setData = nil;
    setSize = 0;
}

#define PRINT_COMMA if (print_comma) fprintf(stderr, ", "); print_comma = true
void codeRange::print_range(Address addr) {
   bool print_comma = false;
   image *img_ptr = is_image();
   mapped_object *mapped_ptr = is_mapped_object();
	int_function *func_ptr = is_function();
   functionReplacement *reloc_ptr = is_function_replacement();
   multiTramp *multi_ptr = is_multitramp();
   baseTrampInstance *base_ptr = NULL;
	miniTrampInstance *mini_ptr = is_minitramp();
   inferiorRPCinProgress *rpc_ptr = is_inferior_rpc();

   /**
    * The is_* functions above won't give us mulitple layers of objects
    * (i.e the fact we have a function pointer, doesn't mean we have a 
    * mapped_object pointer).  Build up more information from what we have
    **/
   if (mini_ptr && !base_ptr) 
      base_ptr = mini_ptr->baseTI;
   if (base_ptr && !multi_ptr)
      multi_ptr = base_ptr->multiT;
   if (multi_ptr && !func_ptr) 
      func_ptr = multi_ptr->func();
   if (multi_ptr && !base_ptr && addr) 
      base_ptr = multi_ptr->getBaseTrampInstanceByAddr(addr);
   if (reloc_ptr && !func_ptr)
      func_ptr = reloc_ptr->source()->func();
   if (func_ptr && !mapped_ptr)
      mapped_ptr = func_ptr->obj();
   if (mapped_ptr && !img_ptr)
      img_ptr = mapped_ptr->parse_img();

   fprintf(stderr, "[");

   if (img_ptr) {
      PRINT_COMMA;
      fprintf(stderr, "img:%s", img_ptr->name().c_str());
   }
   if (mapped_ptr) {
      PRINT_COMMA;
      fprintf(stderr, "map_obj:%s", mapped_ptr->fullName().c_str());
   }
   if (func_ptr) {
      PRINT_COMMA;
      fprintf(stderr, "func:%s", func_ptr->prettyName().c_str());
   }
   if (reloc_ptr) {
      PRINT_COMMA;
      fprintf(stderr, "reloc:%x", 
              reloc_ptr->targetVersion());
   }
   if (multi_ptr) {
      PRINT_COMMA;
      fprintf(stderr, "multi:%p->%p+%u", (void *)multi_ptr->instAddr(), 
              (void *)multi_ptr->get_address_cr(), multi_ptr->get_size_cr());
   }
   if (base_ptr) {
      PRINT_COMMA;
      fprintf(stderr, "base:%p+%u", (void *)multi_ptr->get_address_cr(),
              multi_ptr->get_size_cr());
   }
   if (mini_ptr) {
      PRINT_COMMA;
      fprintf(stderr, "mini:%p+%u", (void *)multi_ptr->get_address_cr(),
              multi_ptr->get_size_cr());
   }
   if (rpc_ptr) {
      PRINT_COMMA;
      fprintf(stderr, "rpc:%lx", rpc_ptr->get_address_cr());
   }
   if (!print_comma)
   {
      fprintf(stderr, "Nothing");
   }
   fprintf(stderr, "]\n");
}

